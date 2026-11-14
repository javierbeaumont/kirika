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
	"slices"
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

// A session reads back as written. A value of another format, of a class other than correct pages', malformed, with no
// visit or with a time outside the years 1 to 9999 reads as none.
func TestSessionCodec(t *testing.T) {
	for _, clientSession := range []session{
		{class: humanVisits, host: "h", visits: []visit{{exit: "/b", last: 1}}},
		{
			class:  newClass(true, groupCorrect),
			visits: []visit{{last: firstVisitTime}, {exit: "/b", last: lastVisitTime}},
		},
	} {
		if got, ok := decodeSession(encodeSession(clientSession)); !ok || !reflect.DeepEqual(got, clientSession) {
			t.Errorf("round trip of %+v = %+v, %v", clientSession, got, ok)
		}
	}

	good := encodeSession(session{class: humanVisits, host: "h", visits: []visit{{exit: "/b", last: 1}}})
	upTo := func(end int, more ...byte) []byte { return append(slices.Clone(good[:end]), more...) }
	withClass := func(visitClass class) []byte { return append([]byte{sessionVersion, byte(visitClass)}, good[2:]...) }
	withLast := func(last int64) []byte {
		return encodeSession(session{class: humanVisits, host: "h", visits: []visit{{exit: "/b", last: last}}})
	}

	for name, encoded := range map[string][]byte{
		"empty":           {},
		"no class":        {sessionVersion},
		"version 0":       append([]byte{0}, good[1:]...),
		"error class":     withClass(newClass(false, groupError)),
		"unknown class":   withClass(numClasses),
		"no host":         upTo(2),
		"host too long":   upTo(2, 5, 'h'),
		"no visit":        upTo(4),
		"cut varint":      upTo(4, 0x80),
		"varint overflow": upTo(4, bytes.Repeat([]byte{0xff}, 11)...),
		"no exit":         upTo(5),
		"exit too long":   upTo(5, 9, '/', 'b'),
		"trailing byte":   upTo(len(good), 0),
		"before year 1":   withLast(firstVisitTime - 1),
		"after year 9999": withLast(lastVisitTime + 1),
	} {
		if _, ok := decodeSession(encoded); ok {
			t.Errorf("%s %x: decoded", name, encoded)
		}
	}
}

// The seconds between two Unix times are the same in either order.
func TestDistance(t *testing.T) {
	if distance(5, 2) != 3 || distance(2, 5) != 3 || distance(4, 4) != 0 {
		t.Errorf("distance of 5 and 2, 2 and 5, 4 and 4 = %d, %d, %d; want 3, 3, 0", distance(5, 2), distance(2, 5),
			distance(4, 4))
	}
}

// A page joins the open visit whose latest page is nearest, if no more than the timeout before or after it in whole
// seconds; else it opens a visit, counted with its entry page, and the other visits stay open. The page becomes its
// visit's latest unless it is older. Of two visits equally near, it joins the one whose latest page is before it.
func TestAddPage(t *testing.T) {
	batch := batchIn(time.UTC, DefaultOptions())
	start := base.Unix()
	hour := int64(time.Hour / time.Second)

	for _, tc := range []struct {
		name   string
		visits []visit
		page   time.Time
		want   []visit
		opened bool
	}{
		{"first page", nil, base, []visit{{"/p", start}}, true},
		{"a timeout after", []visit{{"/a", start}}, base.Add(time.Hour), []visit{{"/p", start + hour}}, false},
		{"a timeout before", []visit{{"/a", start + hour}}, base, []visit{{"/a", start + hour}}, false},
		{
			"a fraction past the timeout",
			[]visit{{"/a", start}},
			base.Add(time.Hour + 999*time.Millisecond),
			[]visit{{"/p", start + hour}},
			false,
		},
		{
			"a second past the timeout",
			[]visit{{"/a", start}},
			base.Add(time.Hour + time.Second),
			[]visit{{"/a", start}, {"/p", start + hour + 1}},
			true,
		},
		{
			"nearest of two, the later",
			[]visit{{"/a", start}, {"/b", start + hour*5/3}},
			base.Add(55 * time.Minute),
			[]visit{{"/a", start}, {"/b", start + hour*5/3}},
			false,
		},
		{
			"nearest of two, the earlier",
			[]visit{{"/a", start}, {"/b", start + hour*5/3}},
			base.Add(45 * time.Minute),
			[]visit{{"/p", start + hour*3/4}, {"/b", start + hour*5/3}},
			false,
		},
		{
			"two equally near, the earlier first",
			[]visit{{"/a", start}, {"/b", start + 2*hour}},
			base.Add(time.Hour),
			[]visit{{"/p", start + hour}, {"/b", start + 2*hour}},
			false,
		},
		{
			"two equally near, the later first",
			[]visit{{"/b", start + 2*hour}, {"/a", start}},
			base.Add(time.Hour),
			[]visit{{"/b", start + 2*hour}, {"/p", start + hour}},
			false,
		},
	} {
		tallies := map[string]tally{}
		clientSession := session{class: humanVisits, host: "h", visits: slices.Clone(tc.visits)}
		addPage(&clientSession, sessEvent{humanVisits, "h", "c", "/p", tc.page}, batch, tallies)

		if !reflect.DeepEqual(clientSession.visits, tc.want) {
			t.Errorf("%s: visits = %+v, want %+v", tc.name, clientSession.visits, tc.want)
		}

		entry := dimKey(tagEntry, "h", tc.page.Format("200601"), "/p")
		if opened := len(tallies[string(entry)]) > 0; opened != tc.opened {
			t.Errorf("%s: opened a visit = %v, want %v", tc.name, opened, tc.opened)
		}
	}
}

// A visit ends when it is more than the timeout behind its host's newest page in the batch, or more than abandonedAfter
// before or after the batch's newest page, whatever its host. Then its exit counts and it leaves the session.
func TestEndVisits(t *testing.T) {
	batch := batchIn(time.UTC, DefaultOptions())
	start := base.Unix()
	hour := int64(time.Hour / time.Second)
	abandoned := int64(abandonedAfter / time.Second)
	old := base.AddDate(-50, 0, 0).Unix() // a negative Unix time

	for _, tc := range []struct {
		name, host string
		newest     int64
		last       int64
		ends       bool
	}{
		{"a timeout behind its host's newest", "h", start, start - hour, false},
		{"a second more", "h", start, start - hour - 1, true},
		{"ahead of its host's newest", "h", start, start + 2*hour, false},
		{"another host, abandonedAfter behind", "q", start, start - abandoned, false},
		{"another host, a second more", "q", start, start - abandoned - 1, true},
		{"another host, abandonedAfter ahead", "q", start, start + abandoned, false},
		{"another host, a second further", "q", start, start + abandoned + 1, true},
		{"another host, before 1970", "q", old, old - 2*hour, false},
	} {
		tallies := map[string]tally{}
		clientSession := session{class: humanVisits, host: tc.host, visits: []visit{{"/p", tc.last}}}
		newest := newestPages{all: tc.newest, byHost: map[string]int64{"h": tc.newest}}
		ended := endVisits(&clientSession, newest, batch, tallies)

		if (ended == 1) != tc.ends || (len(clientSession.visits) == 0) != tc.ends || (len(tallies) == 1) != tc.ends {
			t.Errorf("%s: %d ended, %d left, %d exits; want ended = %v", tc.name, ended, len(clientSession.visits),
				len(tallies), tc.ends)
		}
	}
}

// A visit's exit counts once, under its session's host and class, in the month of its latest page in the zone given.
func TestEndVisit(t *testing.T) {
	tallies := map[string]tally{}
	ahead := time.FixedZone("UTC+13", 13*60*60)
	endVisit(tallies, session{class: humanVisits, host: "h"}, visit{"/p", base.Add(-time.Hour).Unix()}, ahead)

	key := string(dimKey(tagExit, "h", base.Format("200601"), "/p"))
	if want := map[string]tally{key: {{humanVisits, Counts{Visits: 1}}}}; !reflect.DeepEqual(tallies, want) {
		t.Errorf("exits = %+v, want %+v", tallies, want)
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
