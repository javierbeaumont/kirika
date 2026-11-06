// kirika: private analytics from HTTP access logs
//
// Copyright (C) 2026 Javier Beaumont <javierbeaumont@users.noreply.github.com>
//
// This file is part of kirika.
//
// kirika is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// kirika is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with kirika. If not, see <https://www.gnu.org/licenses/>.

package kvstore

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// The size in bytes of the store's salt, the key of the session IDs.
const saltLen = 16

// The format of a session value this build writes.
const sessionVersion = 1

var errSaltCorrupt = errors.New("kvstore: corrupt salt")

// What a batch keeps of a correct page for the visits, in memory only.
type sessEvent struct {
	class              class
	host, client, path string
	t                  time.Time // in the store's zone
}

// A client's open visit.
type session struct {
	class class  // of its visits: correct, from a human or a bot
	exit  string // its latest page
	host  string
	last  int64 // Unix time of its latest page
}

// Keeps the store's salt in db, generating it on the first open. It never changes: a new salt would split every open
// visit in two.
func (db *DB) loadSalt(meta *bolt.Bucket) error {
	s := meta.Get(metaSalt)

	switch {
	case s == nil:
		s = make([]byte, saltLen)
		_, _ = rand.Read(s) // never fails

		if err := meta.Put(metaSalt, s); err != nil {
			return err
		}
	case len(s) != saltLen:
		return fmt.Errorf("%w: %d bytes, want %d", errSaltCorrupt, len(s), saltLen)
	}

	db.salt = bytes.Clone(s)

	return nil
}

// Returns the key of a client's session: an HMAC of its host, the client and the class of its visits under the salt,
// cut to 16 bytes. A plain hash of an IPv4 address falls to trying them all.
func sessionID(salt []byte, host, client string, cl class) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write(encKey(host, client, string([]byte{byte(cl)})))

	return m.Sum(nil)[:16]
}

// Writes s as its format version, its class, its last time as a varint, then its host and exit, each after its length.
func encodeSession(s session) []byte {
	b := binary.AppendVarint([]byte{sessionVersion, byte(s.class)}, s.last)
	for _, str := range [...]string{s.host, s.exit} {
		b = binary.AppendUvarint(b, uint64(len(str)))
		b = append(b, str...)
	}

	return b
}

// Reads a value written by encodeSession, with the class of correct pages; for anything else, ok is false.
func decodeSession(b []byte) (s session, ok bool) {
	if len(b) < 2 || b[0] != sessionVersion {
		return session{}, false
	}

	cl := class(b[1])
	if cl >= numClasses || cl.group() != groupCorrect {
		return session{}, false
	}

	last, n := binary.Varint(b[2:])
	if n <= 0 {
		return session{}, false
	}

	var strs [2]string

	rest := b[2+n:]
	for i := range strs {
		size, n := binary.Uvarint(rest)
		if n <= 0 || size > uint64(len(rest)-n) {
			return session{}, false
		}

		strs[i] = string(rest[n : n+int(size)])
		rest = rest[n+int(size):]
	}

	if len(rest) != 0 {
		return session{}, false
	}

	return session{class: cl, exit: strs[1], host: strs[0], last: last}, true
}

// Adds the batch's visits and their entry and exit pages to d. A page opens a visit when its client has no readable
// session in its class, or when it is more than the visit timeout from the session's latest page, before or after it.
// The previous visit then ends, and its latest page is the exit. Last, every session that far from the batch's newest
// page ends and is deleted.
func sessions(bkt *bolt.Bucket, salt []byte, b *Batch, d map[string]tally) error {
	if len(b.events) == 0 {
		return nil
	}

	var newest time.Time

	for _, e := range b.events {
		key := sessionID(salt, e.host, e.client, e.class)

		s, ok := decodeSession(bkt.Get(key))

		switch {
		case !ok || apart(e.t, time.Unix(s.last, 0), b.timeout):
			if ok {
				endVisit(d, s, b.loc)
			}

			visit := Counts{Visits: 1}
			addTo(d, timeKey(tagHour, e.host, e.t.Format("2006010215")), e.class, visit)
			addTo(d, timeKey(tagDay, e.host, e.t.Format("20060102")), e.class, visit)
			addTo(d, dimKey(tagEntry, e.host, e.t.Format("200601"), e.path), e.class, visit)
			s = session{class: e.class, exit: e.path, host: e.host, last: e.t.Unix()}
		case e.t.Unix() >= s.last:
			s.last, s.exit = e.t.Unix(), e.path
		}

		if err := bkt.Put(key, encodeSession(s)); err != nil {
			return err
		}

		if e.t.After(newest) {
			newest = e.t
		}
	}

	var ended [][]byte

	cur := bkt.Cursor()
	for k, v := cur.First(); k != nil; k, v = cur.Next() {
		s, ok := decodeSession(v)
		if ok && !apart(newest, time.Unix(s.last, 0), b.timeout) {
			continue
		}

		if ok {
			endVisit(d, s, b.loc)
		}

		ended = append(ended, bytes.Clone(k))
	}

	for _, k := range ended {
		if err := bkt.Delete(k); err != nil {
			return err
		}
	}

	return nil
}

// Reports whether a and b are more than d apart, in either order.
func apart(a, b time.Time, d time.Duration) bool {
	return a.Sub(b) > d || b.Sub(a) > d
}

// Adds a visit's latest page to the exit pages of the month it came in, in loc.
func endVisit(d map[string]tally, s session, loc *time.Location) {
	ym := time.Unix(s.last, 0).In(loc).Format("200601")
	addTo(d, dimKey(tagExit, s.host, ym, s.exit), s.class, Counts{Visits: 1})
}
