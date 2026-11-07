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

package ingest

import (
	"bufio"
	"errors"
	"hash/fnv"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/javierbeaumont/kirika/internal/kvstore"
	"github.com/javierbeaumont/kirika/internal/logparse"
)

// Returns FNV-1a of 64 bits over s.
func fnv64(s string) (sum [8]byte) {
	h := fnv.New64a()
	h.Write([]byte(s))
	copy(sum[:], h.Sum(nil))

	return sum
}

// A line's text leaves out its newline and one carriage return before it, wherever the reader's buffer splits them, and
// its checksum covers that text. The reader stops right after the line.
func TestNext(t *testing.T) {
	x := strings.Repeat("x", 15) // with the reader's 16 bytes, the next byte ends its first chunk

	for _, tc := range []struct{ in, text string }{
		{"a\n", "a"},
		{"a\r\n", "a"},
		{"a\r\r\n", "a\r"},
		{"a\rb\n", "a\rb"},
		{"\n", ""},
		{x + "\r\n", x},
		{x + "\ry\n", x + "\ry"},
		{x + "\r\r\n", x + "\r"},
		{x + "\r" + strings.Repeat("y", 20) + "\n", x + "\r" + strings.Repeat("y", 20)},
		{strings.Repeat("y", 40) + "\n", strings.Repeat("y", 40)},
	} {
		br := bufio.NewReaderSize(strings.NewReader(tc.in+"z\n"), 16)

		l, n, more, err := next(br, 7)
		if err != nil || !more || l.long || string(l.text) != tc.text || l.sum != fnv64(tc.text) || l.start != 7 ||
			n != int64(len(tc.in)) {
			t.Errorf("next(%q) = %+v, %d, %v, %v; want text %q, %d bytes", tc.in, l, n, more, err, tc.text, len(tc.in))
		}

		if l, _, _, _ := next(br, 7+n); string(l.text) != "z" {
			t.Errorf("after %q: next line %q, want \"z\"", tc.in, l.text)
		}
	}
}

// A line longer than maxLine keeps no text, but its length and checksum cover it all.
func TestNextLong(t *testing.T) {
	for size, long := range map[int]bool{maxLine: false, maxLine + 1: true} {
		in := strings.Repeat("x", size) + "\r\n"

		l, n, more, err := next(bufio.NewReader(strings.NewReader(in)), 0)
		if err != nil || !more || l.long != long || n != int64(len(in)) || l.sum != fnv64(in[:size]) {
			t.Errorf("a line of %d bytes: long %v, %d bytes read, more %v, %v", size, l.long, n, more, err)
		}

		if want := size; long && l.text != nil || !long && len(l.text) != want {
			t.Errorf("a line of %d bytes keeps %d", size, len(l.text))
		}
	}
}

// The end of the log is no line, even after a last line with no newline, and a read error is the reader's.
func TestNextEnd(t *testing.T) {
	for _, in := range []string{"", "partial"} {
		if _, n, more, err := next(bufio.NewReader(strings.NewReader(in)), 0); more || err != nil ||
			n != int64(len(in)) {
			t.Errorf("next(%q): %d bytes, more %v, %v; want no line", in, n, more, err)
		}
	}

	failure := errors.New("disk")
	if _, _, more, err := next(bufio.NewReader(iotest.ErrReader(failure)), 0); more || !errors.Is(err, failure) {
		t.Errorf("next on a failing reader: more %v, %v; want %v", more, err, failure)
	}
}

// The methods counted by default are HTTP's but TRACE and CONNECT, PATCH and WebDAV's, in upper case, and each call
// returns them anew.
func TestDefaultMethods(t *testing.T) {
	got := DefaultMethods()
	want := []string{
		"COPY", "DELETE", "GET", "HEAD", "LOCK", "MKCOL", "MOVE", "OPTIONS", "PATCH", "POST", "PROPFIND", "PROPPATCH",
		"PUT", "UNLOCK",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DefaultMethods = %q, want %q", got, want)
	}

	got[0] = "TRACE"

	if DefaultMethods()[0] != "COPY" {
		t.Error("DefaultMethods shares its slice between calls")
	}

	if o := DefaultOptions(); !reflect.DeepEqual(o.Methods, want) || !reflect.DeepEqual(o.Count,
		kvstore.DefaultOptions()) {
		t.Errorf("DefaultOptions = %+v, want the default methods and counting rules", o)
	}
}

// A line is too long, blank or binary before it is parsed; then not an access or malformed as the parser says; then
// dropped for its method, or unreadable for its date; else counted, under the default host when its log names none.
func TestJudge(t *testing.T) {
	limit, old := base.Add(ahead), base.AddDate(-1000, 0, 0)
	errBad := errors.New("bad")
	methods := map[string]bool{"GET": true}

	for _, tc := range []struct {
		name string
		l    line
		ev   logparse.Event
		want fate
	}{
		{"too long", line{long: true}, logparse.Event{Method: "GET", Time: base}, tooLong},
		{"empty", line{}, logparse.Event{Method: "GET", Time: base}, blank},
		{"spaces", line{text: []byte(" \t")}, logparse.Event{Method: "GET", Time: base}, blank},
		{"NUL", line{text: []byte("\x00ok")}, logparse.Event{Method: "GET", Time: base}, binary},
		{"not an access", line{text: []byte("other")}, logparse.Event{}, notAccess},
		{"malformed", line{text: []byte("bad")}, logparse.Event{}, malformed},
		{"method out", line{text: []byte("ok")}, logparse.Event{Method: "TRACE", Time: base}, dropped},
		{"lower case", line{text: []byte("ok")}, logparse.Event{Method: "get", Time: base}, dropped},
		{"at the limit", line{text: []byte("ok")}, logparse.Event{Method: "GET", Time: limit}, counted},
		{"past the limit", line{text: []byte("ok")}, logparse.Event{Method: "GET", Time: limit.Add(1)}, badDate},
		{"year 1000", line{text: []byte("ok")}, logparse.Event{Method: "GET", Time: old}, counted},
		{"year 999", line{text: []byte("ok")}, logparse.Event{Method: "GET", Time: old.AddDate(-1, 0, 0)}, badDate},
		{"no host", line{text: []byte("ok")}, logparse.Event{Method: "GET", Time: base}, counted},
		{"a host", line{text: []byte("ok")}, logparse.Event{Host: "h", Method: "GET", Time: base}, counted},
	} {
		parse := func(b []byte) (logparse.Event, error) {
			switch string(b) {
			case "ok":
				return tc.ev, nil
			case "other":
				return logparse.Event{}, logparse.ErrNotAccessLog
			}

			return logparse.Event{}, errBad
		}

		ev, f, why := judge(tc.l, parse, methods, "default", limit)
		if f != tc.want || (f == malformed) != errors.Is(why, errBad) || f != malformed && why != nil {
			t.Errorf("%s: fate %v, %v; want %v", tc.name, f, why, tc.want)
		}

		if want := map[string]string{"": "default", "h": "h"}[tc.ev.Host]; f == counted && ev.Host != want {
			t.Errorf("%s: host %q, want %q", tc.name, ev.Host, want)
		}
	}
}

// Each fate adds to its own counter.
func TestResultAdd(t *testing.T) {
	for f, want := range map[fate]Result{
		counted:   {Counted: 1},
		blank:     {Blank: 1},
		notAccess: {NotAccess: 1},
		dropped:   {Dropped: 1},
		malformed: {Malformed: 1},
		binary:    {Binary: 1},
		tooLong:   {TooLong: 1},
		badDate:   {BadDate: 1},
	} {
		var got Result
		if got.add(f); got != want {
			t.Errorf("add(%v) = %+v, want %+v", f, got, want)
		}
	}
}
