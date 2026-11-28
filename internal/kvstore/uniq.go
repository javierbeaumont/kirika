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
	"errors"
	"fmt"
	"hash"
	"strconv"
	"time"

	"github.com/axiomhq/hyperloglog"
	bolt "go.etcd.io/bbolt"
)

// The precision of a sketch: 2^12 registers, a standard error of about 1.6%, in at most about 4 KB.
const hllPrecision = 12

// The size in bytes of a year's key.
const yearKeyLen = 32

// A sketch's class, host, YYYYMM month and that month's year.
type sketchID struct {
	class       class
	host, month string
	year        int
}

var (
	errClosedCorrupt = errors.New("kvstore: corrupt last closed year")
	errDayUnique     = errors.New("kvstore: unique visitors are kept per month, not per day")
)

// Returns an empty sketch, sparse until it grows.
func newSketch() *hyperloglog.Sketch {
	sk, err := hyperloglog.NewSketch(hllPrecision, true)
	if err != nil {
		panic(err) // hllPrecision is within the library's range
	}

	return sk
}

// Returns the key of the sketch of a host, month and class: encKey(host, YYYYMM) and the class.
func uniqKey(host, ym string, cl class) []byte {
	return append(encKey(host, ym), byte(cl))
}

// Adds a client to the batch's unique visitors of a host, month and class.
func (b *Batch) addUnique(host, month string, year int, trafficClass class, client string) {
	id := sketchID{trafficClass, host, month, year}

	clients := b.uniques[id]
	if clients == nil {
		clients = map[string]bool{}
		b.uniques[id] = clients
	}

	clients[client] = true
}

// Decodes a copy of a stored blob, since bbolt owns the original. ok is false for a blob that does not decode or holds
// another precision.
func loadSketch(blob []byte) (sk *hyperloglog.Sketch, ok bool) {
	if len(blob) < 2 || blob[1] != hllPrecision {
		return nil, false
	}

	sk = new(hyperloglog.Sketch)
	if err := sk.UnmarshalBinary(bytes.Clone(blob)); err != nil {
		return nil, false
	}

	return sk, true
}

// Adds the batch's clients to the stored sketches, each as an HMAC-SHA256 under the key of its sketch's year: a sketch
// keeps bits of a hash that only the key repeats. The clients of a year up to lastClosed are left out, as a closed year
// gets no key. An unreadable stored sketch is replaced by a sketch of the batch's clients alone: unique visitors are an
// estimate, and the month counts low rather than failing.
func writeUnique(sketches, keys *bolt.Bucket, uniques map[sketchID]map[string]bool, lastClosed int) error {
	macs := map[int]hash.Hash{} // by year

	var sum [sha256.Size]byte

	for id, clients := range uniques {
		if id.year <= lastClosed {
			continue
		}

		mac := macs[id.year]
		if mac == nil {
			key, err := yearKey(keys, strconv.Itoa(id.year))
			if err != nil {
				return err
			}

			mac = hmac.New(sha256.New, key)
			macs[id.year] = mac
		}

		sketch := newSketch()

		for client := range clients {
			mac.Reset()
			mac.Write([]byte(client))
			sketch.Insert(mac.Sum(sum[:0]))
		}

		sketchKey := uniqKey(id.host, id.month, id.class)
		if stored, ok := loadSketch(sketches.Get(sketchKey)); ok {
			if err := stored.Merge(sketch); err != nil {
				return err
			}

			sketch = stored
		}

		blob, err := sketch.MarshalBinary()
		if err != nil {
			return err
		}

		if err := sketches.Put(sketchKey, blob); err != nil {
			return err
		}
	}

	return nil
}

// Returns the last closed year, or -1 while none is: a page in the store's zone can be of the year 0.
func lastClosedYear(meta *bolt.Bucket) (int, error) {
	stored := meta.Get(metaClosed)
	if stored == nil {
		return -1, nil
	}

	year, err := strconv.Atoi(string(stored))
	if err != nil || year < 0 {
		return 0, fmt.Errorf("%w: %q", errClosedCorrupt, stored)
	}

	return year, nil
}

// Closes the years before the newest page's but, while that page is of January, not the one just before: the month of
// grace lets a log read late count its clients. Their keys are deleted, as is a key with no year, and the last of these
// years is kept as the last closed year. A batch with no page has the zero time as its newest page, which closes none.
func closeYears(meta, keys *bolt.Bucket, newestPage time.Time, lastClosed int) error {
	last := newestPage.Year() - 1
	if newestPage.Month() == time.January {
		last--
	}

	if last <= lastClosed {
		return nil
	}

	var old [][]byte

	cursor := keys.Cursor()
	for name, _ := cursor.First(); name != nil; name, _ = cursor.Next() {
		if year, err := strconv.Atoi(string(name)); err != nil || year <= last {
			old = append(old, bytes.Clone(name))
		}
	}

	for _, name := range old {
		if err := keys.Delete(name); err != nil {
			return err
		}
	}

	return meta.Put(metaClosed, []byte(strconv.Itoa(last)))
}

// Returns the key of a year's sketches, made on the year's first page. A stored key of another size is replaced, and
// the year may then count a client twice.
func yearKey(keys *bolt.Bucket, year string) ([]byte, error) {
	if key := keys.Get([]byte(year)); len(key) == yearKeyLen {
		return key, nil
	}

	key := make([]byte, yearKeyLen)
	_, _ = rand.Read(key) // never fails

	return key, keys.Put([]byte(year), key)
}

// Unique estimates the distinct clients with a page in a class f counts on the given hosts, over a year or a month. A
// client counts once across hosts and across the months of a year. Only pages add clients, so the kind of f changes
// nothing. A day is an error, and an unreadable sketch counts as empty.
func (db *DB) Unique(period string, f Filter, hosts ...string) (uint64, error) {
	date, err := checked(period, f)
	if err != nil {
		return 0, err
	}

	if len(date) == 8 {
		return 0, fmt.Errorf("%w: %q", errDayUnique, period)
	}

	acc := newSketch()

	err = db.file.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(bktUniq)

		for _, host := range hosts {
			for _, ym := range months(date) {
				for cl := range class(numClasses) {
					if !f.has(cl) {
						continue
					}

					if sk, ok := loadSketch(bkt.Get(uniqKey(hostKey(host), ym, cl))); ok {
						if err := acc.Merge(sk); err != nil {
							return err
						}
					}
				}
			}
		}

		return nil
	})
	if err != nil {
		return 0, err
	}

	return acc.Estimate(), nil
}
