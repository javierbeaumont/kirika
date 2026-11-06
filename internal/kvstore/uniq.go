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
	"errors"
	"fmt"

	"github.com/axiomhq/hyperloglog"
	bolt "go.etcd.io/bbolt"
)

// The precision of a sketch: 2^12 registers, a standard error of about 1.6%, in at most 4 KB.
const hllPrecision = 12

var errDayUnique = errors.New("kvstore: unique visitors are kept per month, not per day")

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

// Adds a client to the batch's sketch of a host, month and class. A sketch holds no client, only bits of its hash.
func (b *Batch) addUnique(host, ym string, cl class, client string) {
	k := string(uniqKey(host, ym, cl))

	sk := b.u[k]
	if sk == nil {
		sk = newSketch()
		b.u[k] = sk
	}

	sk.Insert([]byte(client))
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

// Merges the batch's sketches into the stored ones. An unreadable stored sketch is replaced by the batch's: unique
// visitors are an estimate, and the month counts low rather than failing.
func writeUnique(bkt *bolt.Bucket, u map[string]*hyperloglog.Sketch) error {
	for k, sk := range u {
		merged := sk

		if stored, ok := loadSketch(bkt.Get([]byte(k))); ok {
			if err := stored.Merge(sk); err != nil {
				return err
			}

			merged = stored
		}

		blob, err := merged.MarshalBinary()
		if err != nil {
			return err
		}

		if err := bkt.Put([]byte(k), blob); err != nil {
			return err
		}
	}

	return nil
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

	err = db.b.View(func(tx *bolt.Tx) error {
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
