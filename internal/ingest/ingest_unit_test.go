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
	"bytes"
	"errors"
	"hash/fnv"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"
	"time"

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

// The end of the log is no line, even after a last line with no newline, and next returns a failing reader's error.
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

// The methods counted by default are HTTP's but TRACE and CONNECT, PATCH and WebDAV's, in upper case; each call returns
// them anew, and DefaultOptions holds them with the store's default counting rules.
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
	limit := base.Add(ahead)
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
		{"method out, ahead", line{text: []byte("ok")}, logparse.Event{Method: "TRACE", Time: limit.Add(1)}, dropped},
		{"at the limit", line{text: []byte("ok")}, logparse.Event{Method: "GET", Time: limit}, counted},
		{"past the limit", line{text: []byte("ok")}, logparse.Event{Method: "GET", Time: limit.Add(1)}, badDate},
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

		event, judged, why := judge(tc.l, parse, methods, "default", limit, time.UTC)
		if judged != tc.want || (judged == malformed) != errors.Is(why, errBad) || judged != malformed && why != nil {
			t.Errorf("%s: fate %v, %v; want %v", tc.name, judged, why, tc.want)
		}

		if want := map[string]string{"": "default", "h": "h"}[tc.ev.Host]; judged == counted && event.Host != want {
			t.Errorf("%s: host %q, want %q", tc.name, event.Host, want)
		}
	}
}

// A line counts only in the years 1000 to 9999 of the zone, whatever its year in UTC.
func TestJudgeYears(t *testing.T) {
	const east = 14 * time.Hour

	zone := time.FixedZone("+14", int(east.Seconds()))
	// The first instants of the years 1000 and 10000 in zone.
	first, end := base.AddDate(-1000, 0, 0).Add(-east), base.AddDate(8000, 0, 0).Add(-east)

	for _, tc := range []struct {
		name string
		at   time.Time
		want fate
	}{
		{"year 999", first.Add(-time.Second), badDate},
		{"year 1000, 999 in UTC", first, counted},
		{"year 9999", end.Add(-time.Second), counted},
		{"year 10000, 9999 in UTC", end, badDate},
	} {
		parse := func([]byte) (logparse.Event, error) { return logparse.Event{Method: "GET", Time: tc.at}, nil }

		_, judged, _ := judge(line{text: []byte("ok")}, parse, map[string]bool{"GET": true}, "h", end.Add(ahead), zone)
		if judged != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, judged, tc.want)
		}
	}
}

// Each fate adds to its own counter, and an unreadable one to Unreadable too.
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

		if n, want := got.Unreadable(), map[bool]int{true: 1}[f.unreadable()]; n != want {
			t.Errorf("add(%v): Unreadable = %d, want %d", f, n, want)
		}
	}
}

// New refuses counting rules that kvstore.Options.Check refuses, a nil parser, an empty method list and a method that
// is empty or not in upper case.
func TestNewRefuses(t *testing.T) {
	count := kvstore.DefaultOptions()
	noCodes, shortTimeout := count, count
	noCodes.ValidCodes, shortTimeout.VisitTimeout = nil, time.Second-time.Millisecond

	for _, tc := range []struct {
		count   kvstore.Options
		parse   logparse.Parser
		methods []string
		want    string
	}{
		{noCodes, logparse.ParseNCSA, []string{"GET"}, "kvstore: no valid status code"},
		{shortTimeout, logparse.ParseNCSA, []string{"GET"}, "kvstore: visit timeout 999ms is under a second"},
		{count, nil, []string{"GET"}, "ingest: no parser"},
		{count, logparse.ParseNCSA, nil, "ingest: no method to count"},
		{count, logparse.ParseNCSA, []string{}, "ingest: no method to count"},
		{count, logparse.ParseNCSA, []string{"GET", "get"}, `ingest: method "get" is empty or not in upper case`},
		{count, logparse.ParseNCSA, []string{"Get"}, `ingest: method "Get" is empty or not in upper case`},
		{count, logparse.ParseNCSA, []string{""}, `ingest: method "" is empty or not in upper case`},
		{count, logparse.ParseNCSA, []string{"GET", "M-SEARCH"}, ""},
	} {
		o := DefaultOptions()
		o.Count, o.Methods = tc.count, tc.methods

		r, err := New(nil, "access.log", tc.parse, o)

		got := ""
		if err != nil {
			got = err.Error()
		}

		if got != tc.want || (err == nil) != (r != nil) {
			t.Errorf("New with codes %v, timeout %v, parser %v, methods %q: %v; want %q", tc.count.ValidCodes,
				tc.count.VisitTimeout, tc.parse != nil, tc.methods, err, tc.want)
		}
	}
}

// New puts the default host in the form logparse.VHost returns.
func TestNewDefaultHost(t *testing.T) {
	for in, want := range map[string]string{
		"":                  "",
		"example.com":       "example.com",
		"example.com:443":   "example.com",
		"example.com:08080": "example.com:8080",
		"[2001:db8::1]:80":  "2001:db8::1",
	} {
		o := DefaultOptions()
		o.DefaultHost = in

		r, err := New(nil, "access.log", logparse.ParseNCSA, o)
		if err != nil {
			t.Fatalf("New with the default host %q: %v", in, err)
		}

		if r.host != want {
			t.Errorf("the default host %q became %q, want %q", in, r.host, want)
		}
	}
}

// A line's report says what became of it, with a dropped line's method, an unreadable one's parser error, if any, and a
// rotated file's name; below the debug level it builds nothing.
func TestTell(t *testing.T) {
	var logged bytes.Buffer

	options := DefaultOptions()
	options.Log = slog.New(slog.NewTextHandler(&logged, nil))

	quiet, err := New(nil, "/logs/access.log", logparse.ParseNCSA, options)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, errBad := t.Context(), errors.New("bad")

	allocs := testing.AllocsPerRun(100, func() {
		quiet.tell(ctx, "access.log.1", line{start: 1000}, 1000, malformed, "TRACE", errBad)
	})
	if allocs != 0 || logged.Len() != 0 {
		t.Errorf("below the debug level: %v allocations, logged %q; want none", allocs, logged.String())
	}

	options.Log = slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug}))

	loud, err := New(nil, "/logs/access.log", logparse.ParseNCSA, options)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, tc := range []struct {
		judged  fate
		rotated string
		why     error
		want    string
	}{
		{blank, "", nil, `msg="line skipped" path=/logs/access.log line=7 offset=70 reason=blank`},
		{blank, "access.log.1", nil, `msg="line skipped" path=/logs/access.log line=7 offset=70 reason=blank ` +
			"file=access.log.1"},
		{dropped, "", nil, `msg="line dropped" path=/logs/access.log line=7 offset=70 reason="method not counted" ` +
			"method=TRACE"},
		{malformed, "", errBad, `msg="line unreadable" path=/logs/access.log line=7 offset=70 reason=malformed ` +
			"error=bad"},
		{binary, "", nil, `msg="line unreadable" path=/logs/access.log line=7 offset=70 reason=binary`},
	} {
		logged.Reset()
		loud.tell(ctx, tc.rotated, line{start: 70}, 7, tc.judged, "TRACE", tc.why)

		if got, want := logged.String(), "level=DEBUG "+tc.want+"\n"; !strings.HasSuffix(got, want) {
			t.Errorf("the report of a line %v in %q = %q, want it to end in %q", tc.judged, tc.rotated, got, want)
		}
	}
}
