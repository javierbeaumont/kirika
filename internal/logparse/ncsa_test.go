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

package logparse

import (
	"bytes"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestParseNCSACombined(t *testing.T) {
	line := `203.0.113.5 - alice [03/Jul/2026:13:55:36 +0000] "GET /blog/post-1?utm=x HTTP/1.1" 200 2326 ` +
		`"https://ref.example/page" "Mozilla/5.0 (X11; Linux x86_64)"`

	got, err := ParseNCSA([]byte(line))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if got.ClientIP != "203.0.113.5" {
		t.Errorf("ClientIP = %q, want 203.0.113.5", got.ClientIP)
	}

	if got.Host != "" {
		t.Errorf("Host = %q, want empty (NCSA has no vhost)", got.Host)
	}

	if got.Method != "GET" || got.Path != "/blog/post-1" || got.Proto != "HTTP/1.1" || got.URI != "/blog/post-1?utm=x" {
		t.Errorf("request parse mismatch: %+v", got)
	}

	if got.Referer != "https://ref.example/page" || got.UserAgent != "Mozilla/5.0 (X11; Linux x86_64)" {
		t.Errorf("referer/ua mismatch: %q / %q", got.Referer, got.UserAgent)
	}

	if got.Size != 2326 || got.Status != 200 {
		t.Errorf("size/status = %d/%d, want 2326/200", got.Size, got.Status)
	}

	if got.Time.Hour() != 13 || got.Time.Month() != 7 || got.Time.Year() != 2026 {
		t.Errorf("time parse mismatch: %v", got.Time)
	}
}

func TestParseNCSACommon(t *testing.T) {
	// Common Log Format: no referer/user-agent, and a "-" byte count.
	line := `127.0.0.1 - - [03/Jul/2026:09:00:00 +0000] "POST /api/login HTTP/1.1" 401 -`

	got, err := ParseNCSA([]byte(line))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if got.Method != "POST" || got.Path != "/api/login" || got.Status != 401 {
		t.Errorf("mismatch: %+v", got)
	}

	if got.Referer != "" || got.UserAgent != "" {
		t.Errorf("common format should have no referer/ua, got %q / %q", got.Referer, got.UserAgent)
	}

	if got.Size != 0 {
		t.Errorf("Size = %d, want 0 for '-'", got.Size)
	}
}

func TestParseNCSAErrors(t *testing.T) {
	for _, bad := range []string{
		"",
		"not a log line",
		`1.2.3.4 - - [03/Jul/2026:13:55:36 +0000] "GET / HTTP/1.1"`,         // no status
		`1.2.3.4 - - [03/Jul/2026:13:55:36 +0000] "GET / HTTP/1.1 200 1`,    // unterminated quote
		`1.2.3.4 - - [03/Jul/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 abc`, // non-numeric size
		`1.2.3.4 - - [03/Jul/2026:13:55:36 +0000] "GET / HTTP/1.1" 20x 1`,   // non-numeric status
		`1.2.3.4 - - [03/Jul/2026:13:55:36 +0000 "GET / HTTP/1.1" 200 1`,    // unterminated [
		`1.2.3.4 - - [not a time] "GET / HTTP/1.1" 200 1`,
		`1.2.3.4 - - missing-brackets "GET / HTTP/1.1" 200 1`,
		`1.2.3.4 - - [03/Jul/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 -1`,                   // negative size
		`1.2.3.4 - - [03/Jul/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 +1`,                   // signed size
		`1.2.3.4 - - [03/Jul/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 9223372036854775808`,  // size overflows int64
		`1.2.3.4 - - [03/Jul/2026:13:55:36 +0000] "GET / HTTP/1.1" -200 1`,                   // negative status
		`1.2.3.4 - - [03/Jul/2026:13:55:36 +0000] "GET / HTTP/1.1" +200 1`,                   // signed status
		`1.2.3.4 - - [03/Jul/2026:13:55:36 +0000] "GET / HTTP/1.1" 99 1`,                     // status below 100
		`1.2.3.4 - - [03/Jul/2026:13:55:36 +0000] "GET / HTTP/1.1" 1000 1`,                   // status above 999
		`1.2.3.4 - - [03/Jul/2026:13:55:36 +0000] "GET / HTTP/1.1" 70000 1`,                  // status overflows
		`1.2.3.4 - - [03/Jul/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 1 "https://r.example`, // unterminated referer
		`1.2.3.4 - - [03/Jul/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 1 "-" "agent`,         // unterminated user agent
		`1.2.3.4 - - [01/Jan/0001:00:00:00 +0100] "GET / HTTP/1.1" 200 1`,                    // year 0 in UTC
	} {
		if _, err := ParseNCSA([]byte(bad)); err == nil {
			t.Errorf("ParseNCSA(%q): want error, got nil", bad)
		}
	}
}

func TestParseNCSAEscapedQuote(t *testing.T) {
	line := `1.2.3.4 - - [03/Jul/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 1 "-" "agent \"quoted\" \\ end"`

	got, err := ParseNCSA([]byte(line))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if want := `agent "quoted" \ end`; got.UserAgent != want {
		t.Errorf("UserAgent = %q, want %q", got.UserAgent, want)
	}
}

// TestParseNCSAFixture parses real nginx Combined lines (testdata/nginx_access.log).
func TestParseNCSAFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/nginx_access.log")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	if len(lines) != 3 {
		t.Fatalf("fixture: got %d lines, want 3", len(lines))
	}

	events := make([]Event, len(lines))
	for i, l := range lines {
		ev, err := ParseNCSA(l)
		if err != nil {
			t.Fatalf("line %d: unexpected error: %v", i, err)
		}

		events[i] = ev
	}

	// Fields shared by every fixture line.
	for i, ev := range events {
		if ev.ClientIP != "172.18.0.1" {
			t.Errorf("line %d: ClientIP = %q, want 172.18.0.1", i, ev.ClientIP)
		}

		if ev.Host != "" {
			t.Errorf("line %d: Host = %q, want empty (no vhost in NCSA)", i, ev.Host)
		}
	}

	// Line 0: GET / 200, no referer ("-" -> "").
	if got := events[0]; got.Method != "GET" || got.Path != "/" || got.Referer != "" || got.Status != 200 ||
		got.UserAgent != "curl/8.7.1" {
		t.Errorf("line 0 mismatch: %+v", got)
	}

	// Line 1: query stripped, real referer and UA.
	if got := events[1]; got.Path != "/blog/post-1" || got.Referer != "https://ref.example/page" ||
		got.URI != "/blog/post-1?utm=x" || got.UserAgent != "Mozilla/5.0 (X11; Linux x86_64)" {
		t.Errorf("line 1 mismatch: %+v", got)
	}

	// Line 2: 404, referer "-" normalised to "".
	if got := events[2]; got.Path != "/missing" || got.Referer != "" || got.Status != 404 {
		t.Errorf("line 2 mismatch: %+v", got)
	}
}

func TestParseNCSANoValue(t *testing.T) {
	line := `1.2.3.4 - - [03/Jul/2026:13:55:36 +0000] "GET / HTTP/1.1" - - "-" "-"`

	got, err := ParseNCSA([]byte(line))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if got.Referer != "" || got.Size != 0 || got.Status != 0 || got.UserAgent != "" {
		t.Errorf(`"-" fields should be empty or 0: %+v`, got)
	}
}

func TestParseNCSARequestLine(t *testing.T) {
	for _, tc := range []struct{ req, method, uri, proto string }{
		{"", "", "", ""},
		{"GET /", "GET", "/", ""},
		{"GET /a?b HTTP/1.1", "GET", "/a?b", "HTTP/1.1"},
	} {
		line := fmt.Sprintf(`1.2.3.4 - - [03/Jul/2026:13:55:36 +0000] %q 200 1`, tc.req)

		got, err := ParseNCSA([]byte(line))
		if err != nil {
			t.Fatalf("request %q: parse: %v", tc.req, err)
		}

		if got.Method != tc.method || got.Proto != tc.proto || got.URI != tc.uri {
			t.Errorf("request %q: method/uri/proto = %q/%q/%q, want %q/%q/%q", tc.req, got.Method, got.URI, got.Proto,
				tc.method, tc.uri, tc.proto)
		}
	}
}

func TestParseNCSATimeZone(t *testing.T) {
	line := `1.2.3.4 - - [03/Jul/2026:15:55:36 +0200] "GET / HTTP/1.1" 200 1`

	got, err := ParseNCSA([]byte(line))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	want := time.Date(2026, 7, 3, 13, 55, 36, 0, time.UTC)
	if !got.Time.Equal(want) || got.Time.Location() != time.UTC {
		t.Errorf("Time = %v, want %v", got.Time, want)
	}
}

func TestParseNCSAEscapes(t *testing.T) {
	for _, tc := range []struct{ field, want string }{
		{`\x22quoted\x22`, `"quoted"`},
		{`ni\xC3\xb1o`, "ni\xc3\xb1o"},
		{`\xZZ`, "xZZ"},
		{`end\x4`, "endx4"},
	} {
		line := `1.2.3.4 - - [03/Jul/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 1 "-" "` + tc.field + `"`

		got, err := ParseNCSA([]byte(line))
		if err != nil {
			t.Fatalf("%s: parse: %v", tc.field, err)
		}

		if got.UserAgent != tc.want {
			t.Errorf("%s: UserAgent = %q, want %q", tc.field, got.UserAgent, tc.want)
		}
	}
}

// TestParseNCSAFields covers the optional and extra fields around the request.
func TestParseNCSAFields(t *testing.T) {
	const prefix = `1.2.3.4 - - [03/Jul/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 1`

	for _, tc := range []struct{ tail, referer, ua string }{
		{` "https://ref.example/"`, "https://ref.example/", ""},
		{` "https://ref.example/" "ua/1" "198.51.100.9"`, "https://ref.example/", "ua/1"},
		{`   "https://ref.example/"   "ua/1"`, "https://ref.example/", "ua/1"},
	} {
		got, err := ParseNCSA([]byte(prefix + tc.tail))
		if err != nil {
			t.Fatalf("%q: parse: %v", tc.tail, err)
		}

		if got.Referer != tc.referer || got.UserAgent != tc.ua {
			t.Errorf("%q: referer/ua = %q/%q, want %q/%q", tc.tail, got.Referer, got.UserAgent, tc.referer, tc.ua)
		}
	}
}

// TestParseNCSARanges accepts the bounds of the status and size fields.
func TestParseNCSARanges(t *testing.T) {
	for _, tc := range []struct {
		status, size string
		wantStatus   int
		wantSize     int64
	}{
		{"100", "0", 100, 0},
		{"999", "9223372036854775807", 999, 9223372036854775807},
	} {
		line := `1.2.3.4 - - [03/Jul/2026:13:55:36 +0000] "GET / HTTP/1.1" ` + tc.status + " " + tc.size

		got, err := ParseNCSA([]byte(line))
		if err != nil {
			t.Fatalf("status %s, size %s: parse: %v", tc.status, tc.size, err)
		}

		if got.Status != tc.wantStatus || got.Size != tc.wantSize {
			t.Errorf("status/size = %d/%d, want %d/%d", got.Status, got.Size, tc.wantStatus, tc.wantSize)
		}
	}
}
