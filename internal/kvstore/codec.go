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
	"encoding/binary"
	"errors"
	"math"
	"sort"
)

// The format of a counter value this build writes.
const countVersion = 1

var errBadValue = errors.New("kvstore: corrupt or unknown counter value")

// Counts holds the counters of one class, or their sum over several. Pages and PageBandwidth are the part of Hits and
// HitBandwidth that pages make; files make the rest.
type Counts struct {
	HitBandwidth  int64 // response bytes
	Hits          int64
	PageBandwidth int64
	Pages         int64
}

// Adds d to c, capping each counter at math.MaxInt64. Counters are never negative.
func (c *Counts) add(d Counts) {
	c.HitBandwidth = addCapped(c.HitBandwidth, d.HitBandwidth)
	c.Hits = addCapped(c.Hits, d.Hits)
	c.PageBandwidth = addCapped(c.PageBandwidth, d.PageBandwidth)
	c.Pages = addCapped(c.Pages, d.Pages)
}

func addCapped(a, b int64) int64 {
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}

	return a + b
}

// Joins the parts of a key, each preceded by its length as a uvarint, so no byte inside a part can be read as a
// boundary between parts.
func encKey(parts ...string) []byte {
	var key []byte
	for _, p := range parts {
		key = binary.AppendUvarint(key, uint64(len(p)))
		key = append(key, p...)
	}

	return key
}

// The counters of one key, one set per class present, in class order.
type tally []classCounts

type classCounts struct {
	class class
	Counts
}

// Adds c to the counters of class cl.
func (t tally) add(cl class, c Counts) tally {
	i := sort.Search(len(t), func(i int) bool { return t[i].class >= cl })
	if i < len(t) && t[i].class == cl {
		t[i].add(c)

		return t
	}

	t = append(t, classCounts{})
	copy(t[i+1:], t[i:])
	t[i] = classCounts{cl, c}

	return t
}

// Writes t as its format version and then, for each class, its byte and one uvarint per counter.
func encodeTally(t tally) []byte {
	b := []byte{countVersion}
	for _, e := range t {
		b = append(b, byte(e.class))
		for _, v := range [...]int64{e.HitBandwidth, e.Hits, e.PageBandwidth, e.Pages} {
			b = binary.AppendUvarint(b, uint64(v))
		}
	}

	return b
}

// Reads a value written by encodeTally: at least one class, in increasing order, with pages within hits.
func decodeTally(b []byte) (tally, error) {
	if len(b) < 2 || b[0] != countVersion {
		return nil, errBadValue
	}

	var t tally

	for rest := b[1:]; len(rest) > 0; {
		cl := class(rest[0])
		if cl >= numClasses || len(t) > 0 && cl <= t[len(t)-1].class {
			return nil, errBadValue
		}

		rest = rest[1:]

		var f [4]int64

		for i := range f {
			v, n := binary.Uvarint(rest)
			if n <= 0 || v > math.MaxInt64 {
				return nil, errBadValue
			}

			f[i] = int64(v)
			rest = rest[n:]
		}

		c := Counts{HitBandwidth: f[0], Hits: f[1], PageBandwidth: f[2], Pages: f[3]}
		if c.Pages > c.Hits || c.PageBandwidth > c.HitBandwidth {
			return nil, errBadValue
		}

		t = append(t, classCounts{cl, c})
	}

	return t, nil
}
