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
	"math"
	"reflect"
	"testing"
)

func TestEncKey(t *testing.T) {
	if bytes.Equal(encKey("a\x01b"), encKey("a", "b")) {
		t.Error("a part holding a length byte collides with two parts")
	}

	if bytes.Equal(encKey("ab", ""), encKey("a", "b")) {
		t.Error("parts split at different points collide")
	}

	if !bytes.HasPrefix(encKey("h", "200001", "/blog"), encKey("h", "200001")) {
		t.Error("a key does not start with the key of its leading parts")
	}

	if got, want := encKey("", "ab"), []byte{0, 2, 'a', 'b'}; !bytes.Equal(got, want) {
		t.Errorf("encKey = %x, want %x", got, want)
	}
}

func TestCountsAdd(t *testing.T) {
	c := Counts{HitBandwidth: math.MaxInt64, Hits: 1, PageBandwidth: 5, Pages: math.MaxInt64 - 1, Visits: 7}
	c.add(Counts{HitBandwidth: math.MaxInt64, Hits: 2, PageBandwidth: math.MaxInt64, Pages: 1, Visits: math.MaxInt64})

	if want := (Counts{math.MaxInt64, 3, math.MaxInt64, math.MaxInt64, math.MaxInt64}); c != want {
		t.Errorf("add = %+v, want %+v", c, want)
	}
}

// A tally keeps one set of counters per class, in class order.
func TestTallyAdd(t *testing.T) {
	var got tally
	for _, cl := range []class{3, 0, 5, 0, 3} {
		got = got.add(cl, Counts{Hits: 1})
	}

	want := tally{{0, Counts{Hits: 2}}, {3, Counts{Hits: 2}}, {5, Counts{Hits: 1}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("tally = %+v, want %+v", got, want)
	}
}

func TestTallyRoundTrip(t *testing.T) {
	for _, tl := range []tally{
		{{0, Counts{}}},
		{{1, Counts{4, 2, 3, 1, 5}}, {numClasses - 1, Counts{HitBandwidth: 9}}},
		{{2, Counts{math.MaxInt64, math.MaxInt64, math.MaxInt64, math.MaxInt64, math.MaxInt64}}},
	} {
		got, err := decodeTally(encodeTally(tl))
		if err != nil || !reflect.DeepEqual(got, tl) {
			t.Errorf("round trip of %+v = %+v, %v", tl, got, err)
		}
	}
}

func TestDecodeTallyErrors(t *testing.T) {
	// The page bytes overflow: as an int64 they would be -1, which no other check refuses.
	maxUint := append([]byte{countVersion, 0, 0, 0}, bytes.Repeat([]byte{0xff}, 9)...)
	maxUint = append(maxUint, 0x01, 0, 0)

	for name, b := range map[string][]byte{
		"empty":            {},
		"no class":         {countVersion},
		"version 0":        {0, 0, 0, 0, 0, 0, 0},
		"newer version":    {countVersion + 1, 0, 0, 0, 0, 0, 0},
		"unknown class":    {countVersion, numClasses, 0, 0, 0, 0, 0},
		"repeated class":   {countVersion, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0},
		"classes reversed": {countVersion, 2, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0},
		"missing counters": {countVersion, 0, 1, 1, 1, 1},
		"cut uvarint":      {countVersion, 0, 1, 1, 1, 1, 0x80},
		"over int64":       maxUint,
		"uvarint overflow": append([]byte{countVersion, 0}, bytes.Repeat([]byte{0xff}, 11)...),
		"pages over hits":  {countVersion, 0, 0, 1, 0, 2, 0},
		"page bytes over":  {countVersion, 0, 1, 0, 2, 0, 0},
	} {
		if _, err := decodeTally(b); !errors.Is(err, errBadValue) {
			t.Errorf("%s %x: err = %v, want errBadValue", name, b, err)
		}
	}
}
