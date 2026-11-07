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

//go:build unit

package kvstore

import (
	"bytes"
	"reflect"
	"testing"
	"time"
)

// A session ID is 16 bytes, the same for the same salt, host, client and class, and another when any of them changes.
func TestSessionID(t *testing.T) {
	salt := bytes.Repeat([]byte{1}, saltLen)

	id := sessionID(salt, "h", "c", humanVisits)
	if len(id) != 16 || !bytes.Equal(sessionID(salt, "h", "c", humanVisits), id) {
		t.Fatalf("sessionID = %x, want 16 bytes, the same each time", id)
	}

	for name, other := range map[string][]byte{
		"salt":        sessionID(bytes.Repeat([]byte{2}, saltLen), "h", "c", humanVisits),
		"host":        sessionID(salt, "g", "c", humanVisits),
		"client":      sessionID(salt, "h", "d", humanVisits),
		"class":       sessionID(salt, "h", "c", newClass(true, groupCorrect)),
		"split parts": sessionID(salt, "hc", "", humanVisits),
	} {
		if bytes.Equal(other, id) {
			t.Errorf("another %s gives the same ID", name)
		}
	}
}

func TestSessionCodec(t *testing.T) {
	for _, s := range []session{
		{},
		{class: newClass(true, groupCorrect), exit: "/b", host: "h", last: -62135596800},
		{last: 1 << 40},
	} {
		if got, ok := decodeSession(encodeSession(s)); !ok || got != s {
			t.Errorf("round trip of %+v = %+v, %v", s, got, ok)
		}
	}

	good := encodeSession(session{class: humanVisits, exit: "/b", host: "h", last: 1})
	withClass := func(cl class) []byte { return append([]byte{sessionVersion, byte(cl)}, good[2:]...) }

	for name, b := range map[string][]byte{
		"empty":           {},
		"no class":        {sessionVersion},
		"version 0":       append([]byte{0}, good[1:]...),
		"error class":     withClass(newClass(false, groupError)),
		"unknown class":   withClass(numClasses),
		"cut varint":      {sessionVersion, 0, 0x80},
		"varint overflow": append([]byte{sessionVersion, 0}, bytes.Repeat([]byte{0xff}, 11)...),
		"missing strings": good[:len(good)-3],
		"string too long": append(append([]byte(nil), good[:len(good)-3]...), 9, '/', 'b'),
		"trailing bytes":  append(append([]byte(nil), good...), 0),
	} {
		if _, ok := decodeSession(b); ok {
			t.Errorf("%s %x: decoded", name, b)
		}
	}
}

// Two times are apart when more than d separates them, in either order.
func TestApart(t *testing.T) {
	d := time.Hour

	for _, tc := range []struct {
		gap  time.Duration
		want bool
	}{{0, false}, {d, false}, {d + time.Nanosecond, true}} {
		if got := apart(base, base.Add(tc.gap), d); got != tc.want {
			t.Errorf("apart of %v later = %v, want %v", tc.gap, got, tc.want)
		}

		if got := apart(base.Add(tc.gap), base, d); got != tc.want {
			t.Errorf("apart of %v earlier = %v, want %v", tc.gap, got, tc.want)
		}
	}
}

// A visit's exit counts once, under its host and class, in the month its latest page was in the batch's zone.
func TestEndVisit(t *testing.T) {
	d := map[string]tally{}
	ahead := time.FixedZone("UTC+13", 13*60*60)
	endVisit(d, session{class: humanVisits, exit: "/p", host: "h", last: base.Add(-time.Hour).Unix()}, ahead)

	key := string(dimKey(tagExit, "h", base.Format("200601"), "/p"))
	if want := map[string]tally{key: {{humanVisits, Counts{Visits: 1}}}}; !reflect.DeepEqual(d, want) {
		t.Errorf("exits = %+v, want %+v", d, want)
	}
}

func TestNewBatchTimeout(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Second} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("NewBatch with a visit timeout of %v did not panic", d)
				}
			}()

			batchIn(time.UTC, Options{VisitTimeout: d})
		}()
	}
}
