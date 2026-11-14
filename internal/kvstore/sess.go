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
	"math"
	"time"

	bolt "go.etcd.io/bbolt"
)

// The size in bytes of the store's salt, the key of the session IDs.
const saltLen = 16

// The format of a session value this build writes.
const sessionVersion = 1

// How far a visit of any host may be before or after a batch's newest page, so neither a host with no more traffic
// keeps its last sessions nor a clock jump keeps a visit ahead open.
const abandonedAfter = 31 * 24 * time.Hour

// The first and last Unix seconds of the years 1 to 9999, the times a visit may hold: any two subtract without
// overflow.
var (
	firstVisitTime = time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	lastVisitTime  = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC).Unix()
)

var errSaltCorrupt = errors.New("kvstore: corrupt salt")

// What a batch keeps of a correct page for the visits, in memory only.
type sessEvent struct {
	class              class
	host, client, path string
	t                  time.Time // in the store's zone
}

// An open visit of a client.
type visit struct {
	exit string // its latest page
	last int64  // Unix time of its latest page
}

// A client's open visits on a host, in one class.
type session struct {
	class  class // of its visits: correct, from a human or a bot
	host   string
	visits []visit
}

// The Unix times of a batch's newest page and of each host's.
type newestPages struct {
	all    int64
	byHost map[string]int64
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

// Writes a session as its format version, its class and its host, then each visit's last time as a varint and its exit;
// a string goes after its length.
func encodeSession(clientSession session) []byte {
	encoded := appendString([]byte{sessionVersion, byte(clientSession.class)}, clientSession.host)
	for _, open := range clientSession.visits {
		encoded = appendString(binary.AppendVarint(encoded, open.last), open.exit)
	}

	return encoded
}

// Appends text after its length as a uvarint.
func appendString(encoded []byte, text string) []byte {
	return append(binary.AppendUvarint(encoded, uint64(len(text))), text...)
}

// Reads a value written by encodeSession, with a class of correct pages and at least one visit, each at a time of the
// years 1 to 9999; for anything else, ok is false.
func decodeSession(encoded []byte) (clientSession session, ok bool) {
	if len(encoded) < 2 || encoded[0] != sessionVersion {
		return session{}, false
	}

	clientSession.class = class(encoded[1])
	if clientSession.class >= numClasses || clientSession.class.group() != groupCorrect {
		return session{}, false
	}

	host, rest, ok := readString(encoded[2:])
	if !ok {
		return session{}, false
	}

	clientSession.host = host

	for len(rest) > 0 {
		last, size := binary.Varint(rest)
		if size <= 0 || last < firstVisitTime || last > lastVisitTime {
			return session{}, false
		}

		exit, after, ok := readString(rest[size:])
		if !ok {
			return session{}, false
		}

		clientSession.visits = append(clientSession.visits, visit{exit: exit, last: last})
		rest = after
	}

	if len(clientSession.visits) == 0 {
		return session{}, false
	}

	return clientSession, true
}

// Splits encoded into a string written by appendString and what follows it; ok is false when it starts with none.
func readString(encoded []byte) (text string, rest []byte, ok bool) {
	size, prefix := binary.Uvarint(encoded)
	if prefix <= 0 || size > uint64(len(encoded)-prefix) {
		return "", nil, false
	}

	end := prefix + int(size)

	return string(encoded[prefix:end]), encoded[end:], true
}

// Adds the batch's visits and their entry and exit pages to tallies. Times compare in whole seconds, as a session keeps
// them.
func sessions(bucket *bolt.Bucket, salt []byte, batch *Batch, tallies map[string]tally) error {
	if len(batch.events) == 0 {
		return nil
	}

	touched := map[string]*session{} // by session ID
	newest := newestPages{all: math.MinInt64, byHost: map[string]int64{}}

	for _, event := range batch.events {
		id := string(sessionID(salt, event.host, event.client, event.class))

		clientSession, found := touched[id]
		if !found {
			stored, ok := decodeSession(bucket.Get([]byte(id)))
			if !ok {
				stored = session{class: event.class, host: event.host}
			}

			clientSession = &stored
			touched[id] = clientSession
		}

		addPage(clientSession, event, batch, tallies)
		newest.add(event.host, event.t.Unix())
	}

	for id, clientSession := range touched {
		if err := storeSession(bucket, []byte(id), *clientSession); err != nil {
			return err
		}
	}

	return endVisitsOf(bucket, newest, batch, tallies)
}

// Adds a page to its client's session: to the open visit whose latest page is nearest, if no more than the timeout
// before or after it, else to a new visit, counted with its entry page. The page becomes its visit's latest unless it
// is older. Of two visits equally near, it joins the one whose latest page is before it.
func addPage(clientSession *session, event sessEvent, batch *Batch, tallies map[string]tally) {
	pageTime := event.t.Unix()
	timeout := int64(batch.timeout / time.Second)
	nearest, nearestGap := -1, int64(0)

	for i, open := range clientSession.visits {
		gap := distance(pageTime, open.last)
		if gap > timeout {
			continue
		}

		if nearest < 0 || gap < nearestGap || gap == nearestGap && open.last < pageTime {
			nearest, nearestGap = i, gap
		}
	}

	switch {
	case nearest < 0:
		count := Counts{Visits: 1}
		addTo(tallies, timeKey(tagHour, event.host, event.t.Format("2006010215")), event.class, count)
		addTo(tallies, timeKey(tagDay, event.host, event.t.Format("20060102")), event.class, count)
		addTo(tallies, dimKey(tagEntry, event.host, event.t.Format("200601"), event.path), event.class, count)
		clientSession.visits = append(clientSession.visits, visit{exit: event.path, last: pageTime})
	case pageTime >= clientSession.visits[nearest].last:
		clientSession.visits[nearest] = visit{exit: event.path, last: pageTime}
	}
}

// Returns the seconds between two Unix times.
func distance(first, second int64) int64 {
	if first > second {
		return first - second
	}

	return second - first
}

// Takes into account a page of host at a Unix time.
func (newest *newestPages) add(host string, pageTime int64) {
	newest.all = max(newest.all, pageTime)

	if hostNewest, ok := newest.byHost[host]; !ok || pageTime > hostNewest {
		newest.byHost[host] = pageTime
	}
}

// Ends the visits of a session more than the timeout behind its host's newest page in the batch, or more than
// abandonedAfter from the batch's newest page, and adds their exits to tallies. Returns how many ended.
func endVisits(clientSession *session, newest newestPages, batch *Batch, tallies map[string]tally) int {
	timeout := int64(batch.timeout / time.Second)
	abandoned := int64(abandonedAfter / time.Second)
	hostNewest, hasPage := newest.byHost[clientSession.host]
	kept := clientSession.visits[:0]

	for _, open := range clientSession.visits {
		if (hasPage && hostNewest-open.last > timeout) || distance(newest.all, open.last) > abandoned {
			endVisit(tallies, *clientSession, open, batch.loc)

			continue
		}

		kept = append(kept, open)
	}

	ended := len(clientSession.visits) - len(kept)
	clientSession.visits = kept

	return ended
}

// Ends the visits of the stored sessions as endVisits does, and deletes the unreadable ones.
func endVisitsOf(bucket *bolt.Bucket, newest newestPages, batch *Batch, tallies map[string]tally) error {
	changed := map[string]session{} // by session ID; an unreadable one has no visit

	cursor := bucket.Cursor()
	for id, value := cursor.First(); id != nil; id, value = cursor.Next() {
		stored, ok := decodeSession(value)
		if ok && endVisits(&stored, newest, batch, tallies) == 0 {
			continue
		}

		changed[string(id)] = stored
	}

	for id, stored := range changed {
		if err := storeSession(bucket, []byte(id), stored); err != nil {
			return err
		}
	}

	return nil
}

// Writes a session under its ID, or deletes it when it has no visit.
func storeSession(bucket *bolt.Bucket, id []byte, clientSession session) error {
	if len(clientSession.visits) == 0 {
		return bucket.Delete(id)
	}

	return bucket.Put(id, encodeSession(clientSession))
}

// Adds an ended visit's latest page to the exit pages of its session's host and class, in the month it came in, in
// zone.
func endVisit(tallies map[string]tally, clientSession session, ended visit, zone *time.Location) {
	month := time.Unix(ended.last, 0).In(zone).Format("200601")
	addTo(tallies, dimKey(tagExit, clientSession.host, month, ended.exit), clientSession.class, Counts{Visits: 1})
}
