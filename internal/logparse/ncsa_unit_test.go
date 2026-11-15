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

package logparse

import (
	"bytes"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestParseNCSACombined(t *testing.T) {
	line := `203.0.113.5 - alice [01/Jan/2000:00:00:00 +0000] "GET /blog/post-1?utm=x HTTP/1.1" 200 2326 ` +
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

	if got.Referer != "https://ref.example/page" || got.UserAgent != "Mozilla/5.0 (X11; Linux x86_64)" ||
		!got.HasUserAgent {
		t.Errorf("referer/ua mismatch: %q / %q, HasUserAgent %v", got.Referer, got.UserAgent, got.HasUserAgent)
	}

	if got.Size != 2326 || got.Status != 200 {
		t.Errorf("size/status = %d/%d, want 2326/200", got.Size, got.Status)
	}

	if got.Time.Hour() != 0 || got.Time.Month() != 1 || got.Time.Year() != 2000 {
		t.Errorf("time parse mismatch: %v", got.Time)
	}
}

// A client loses its port and a path its encoded unreserved characters.
func TestParseNCSANormalized(t *testing.T) {
	got, err := ParseNCSA([]byte(`203.0.113.5:4711 - - [01/Jan/2000:00:00:00 +0000] "GET /%7Ea?%7E HTTP/1.1" 200 1`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	want := Event{ClientIP: "203.0.113.5", Path: "/~a", URI: "/%7Ea?%7E"}
	if got.ClientIP != want.ClientIP || got.Path != want.Path || got.URI != want.URI {
		t.Errorf("ClientIP, Path, URI = %q, %q, %q; want %q, %q, %q", got.ClientIP, got.Path, got.URI, want.ClientIP,
			want.Path, want.URI)
	}
}

func TestParseNCSACommon(t *testing.T) {
	// Common Log Format: no referer/user-agent, and a "-" byte count.
	line := `127.0.0.1 - - [01/Jan/2000:00:00:00 +0000] "POST /api/login HTTP/1.1" 401 -`

	got, err := ParseNCSA([]byte(line))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if got.Method != "POST" || got.Path != "/api/login" || got.Status != 401 {
		t.Errorf("mismatch: %+v", got)
	}

	if got.Referer != "" || got.UserAgent != "" || got.HasUserAgent {
		t.Errorf("common format should have no referer/ua, got %q / %q, HasUserAgent %v", got.Referer, got.UserAgent,
			got.HasUserAgent)
	}

	if got.Size != 0 {
		t.Errorf("Size = %d, want 0 for '-'", got.Size)
	}
}

// Each error names the field it refused, never its value, and the offset where the scan stopped if it could not delimit
// the field.
func TestParseNCSAErrors(t *testing.T) {
	const req = `192.0.2.1 - - [01/Jan/2000:00:00:00 +0000] "GET / HTTP/1.1"`

	for _, tc := range []struct{ line, want string }{
		{"", "ncsa: client is missing at offset 0"},
		{"192.0.2.1", "ncsa: ident is missing at offset 9"},
		{"192.0.2.1 -", "ncsa: authuser is missing at offset 11"},
		{"not a log line", "ncsa: time does not start with [ at offset 14"},
		{`192.0.2.1 - - [01/Jan/2000:00:00:00 +0000 "GET / HTTP/1.1"`, "ncsa: time has no closing ] at offset 58"},
		{`192.0.2.1 - - [not a time] "GET / HTTP/1.1" 200 1`, "ncsa: time is invalid"},
		{`192.0.2.1 - - [01/Jan/2000:00:59:61 +0100] "GET / HTTP/1.1" 200 1`, "ncsa: time is invalid"},
		{`192.0.2.1 - - [01/Jan/0001:00:00:00 +0100] "GET / HTTP/1.1" 200 1`, "ncsa: time is outside years 1-9999"},
		{`192.0.2.1 - - [01/Jan/2000:00:00:00 +0000] GET / 200 1`, "ncsa: request is not quoted at offset 43"},
		{req[:len(req)-1] + ` 200 1`, "ncsa: request has no closing quote at offset 64"},
		{req, "ncsa: status is missing at offset 59"},
		{req + ` 20x 1`, "ncsa: status is not a number"},
		{req + ` -200 1`, "ncsa: status is not a number"},
		{req + ` +200 1`, "ncsa: status is not a number"},
		{req + ` 70000 1`, "ncsa: status is out of range"},
		{req + ` 99 1`, "ncsa: status is not a three-digit code"},
		{req + ` 1000 1`, "ncsa: status is not a three-digit code"},
		{req + ` 200`, "ncsa: size is missing at offset 63"},
		{req + ` 200 abc`, "ncsa: size is not a number"},
		{req + ` 200 -1`, "ncsa: size is not a number"},
		{req + ` 200 +1`, "ncsa: size is not a number"},
		{req + ` 200 9223372036854775808`, "ncsa: size is out of range"},
		{req + ` 200 1 "https://r.example`, "ncsa: referer has no closing quote at offset 84"},
		{req + ` 200 1 "-" "Mozilla`, "ncsa: user agent has no closing quote at offset 78"},
	} {
		if _, err := ParseNCSA([]byte(tc.line)); err == nil || err.Error() != tc.want {
			t.Errorf("ParseNCSA(%q): err = %v, want %q", tc.line, err, tc.want)
		}
	}
}

func TestParseNCSAEscapedQuote(t *testing.T) {
	line := `1.2.3.4 - - [01/Jan/2000:00:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "agent \"quoted\" \\ end"`

	got, err := ParseNCSA([]byte(line))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if want := `agent "quoted" \ end`; got.UserAgent != want {
		t.Errorf("UserAgent = %q, want %q", got.UserAgent, want)
	}
}

// Parses real nginx Combined lines (testdata/nginx_access.log).
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

// Whatever the spaces before the request, a user name with spaces, brackets or an escaped quote shifts no field, nor
// does the " [" of a user agent. Apache logs an empty user name as "".
func TestParseNCSAUserName(t *testing.T) {
	users := []string{`""`, "-", "[x]", "a  b/c", "a [b", "a [b [c", "a [b]", "alice", "alice smith", `x] \"y`}
	for _, user := range users {
		for _, sep := range []string{"", " ", "  "} {
			line := `192.0.2.1 - ` + user + ` [01/Jan/2000:00:00:00 +0000]` + sep +
				`"GET /a HTTP/1.1" 200 1 "-" "Mozilla/4.0 [en]"`

			got, err := ParseNCSA([]byte(line))
			if err != nil {
				t.Fatalf("%s: parse: %v", line, err)
			}

			if got.ClientIP != "192.0.2.1" || got.Path != "/a" || got.Status != 200 || got.Size != 1 {
				t.Errorf("%s: client, path, status, size = %q, %q, %d, %d; want 192.0.2.1, /a, 200, 1", line,
					got.ClientIP, got.Path, got.Status, got.Size)
			}
		}
	}
}

func TestParseNCSANoValue(t *testing.T) {
	line := `1.2.3.4 - - [01/Jan/2000:00:00:00 +0000] "GET / HTTP/1.1" - - "-" "-"`

	got, err := ParseNCSA([]byte(line))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if got.Referer != "" || got.Size != 0 || got.Status != 0 || got.UserAgent != "" {
		t.Errorf(`"-" fields should be empty or 0: %+v`, got)
	}

	if !got.HasUserAgent {
		t.Error(`a "-" user agent is a field the log carries`)
	}
}

func TestParseNCSARequestLine(t *testing.T) {
	for _, tc := range []struct{ req, method, uri, proto string }{
		{"", "", "", ""},
		{"GET /", "GET", "/", ""},
		{"GET /a?b HTTP/1.1", "GET", "/a?b", "HTTP/1.1"},
	} {
		line := fmt.Sprintf(`1.2.3.4 - - [01/Jan/2000:00:00:00 +0000] %q 200 1`, tc.req)

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
	line := `1.2.3.4 - - [01/Jan/2000:00:00:00 +0200] "GET / HTTP/1.1" 200 1`

	got, err := ParseNCSA([]byte(line))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	want := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Add(-2 * time.Hour)
	if !got.Time.Equal(want) || got.Time.Location() != time.UTC {
		t.Errorf("Time = %v, want %v", got.Time, want)
	}
}

// A leap second (second 60) reads as second 59 of its minute, in its time zone.
func TestParseNCSALeapSecond(t *testing.T) {
	line := `1.2.3.4 - - [01/Jan/2000:00:59:60 +0100] "GET / HTTP/1.1" 200 1`

	got, err := ParseNCSA([]byte(line))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	want := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Add(-time.Second)
	if !got.Time.Equal(want) {
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
		line := `1.2.3.4 - - [01/Jan/2000:00:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "` + tc.field + `"`

		got, err := ParseNCSA([]byte(line))
		if err != nil {
			t.Fatalf("%s: parse: %v", tc.field, err)
		}

		if got.UserAgent != tc.want {
			t.Errorf("%s: UserAgent = %q, want %q", tc.field, got.UserAgent, tc.want)
		}
	}
}

// Checks the optional and extra fields around the request.
func TestParseNCSAFields(t *testing.T) {
	const prefix = `1.2.3.4 - - [01/Jan/2000:00:00:00 +0000] "GET / HTTP/1.1" 200 1`

	for _, tc := range []struct {
		tail, referer, userAgent string
		hasUserAgent             bool
	}{
		{` "https://ref.example/"`, "https://ref.example/", "", false},
		{` "https://ref.example/" "ua/1" "198.51.100.9"`, "https://ref.example/", "ua/1", true},
		{`   "https://ref.example/"   "ua/1"`, "https://ref.example/", "ua/1", true},
	} {
		got, err := ParseNCSA([]byte(prefix + tc.tail))
		if err != nil {
			t.Fatalf("%q: parse: %v", tc.tail, err)
		}

		if got.Referer != tc.referer || got.UserAgent != tc.userAgent || got.HasUserAgent != tc.hasUserAgent {
			t.Errorf("%q: referer/ua/HasUserAgent = %q/%q/%v, want %q/%q/%v", tc.tail, got.Referer, got.UserAgent,
				got.HasUserAgent, tc.referer, tc.userAgent, tc.hasUserAgent)
		}
	}
}

// The bounds of the status and size fields are accepted.
func TestParseNCSARanges(t *testing.T) {
	for _, tc := range []struct {
		status, size string
		wantStatus   int
		wantSize     int64
	}{
		{"100", "0", 100, 0},
		{"999", "9223372036854775807", 999, 9223372036854775807},
	} {
		line := `1.2.3.4 - - [01/Jan/2000:00:00:00 +0000] "GET / HTTP/1.1" ` + tc.status + " " + tc.size

		got, err := ParseNCSA([]byte(line))
		if err != nil {
			t.Fatalf("status %s, size %s: parse: %v", tc.status, tc.size, err)
		}

		if got.Status != tc.wantStatus || got.Size != tc.wantSize {
			t.Errorf("status/size = %d/%d, want %d/%d", got.Status, got.Size, tc.wantStatus, tc.wantSize)
		}
	}
}

// The host is the first field without port 80 or 443. The port follows the last colon, as an IPv6 vhost may have no
// brackets. The rest reads as Combined.
func TestParseVHostCombined(t *testing.T) {
	for vhost, want := range map[string]string{
		"2001:db8::1:80":    "2001:db8::1",
		"2001:db8::1:8080":  "[2001:db8::1]:8080",
		"[2001:db8::1]:443": "2001:db8::1",
		"example.com:443":   "example.com",
		"example.com:80":    "example.com",
		"example.com:8080":  "example.com:8080",
	} {
		line := vhost + ` 192.0.2.1 - - [01/Jan/2000:00:00:00 +0000] "GET /a HTTP/1.1" 200 1 "-" "ua/1"`

		got, err := ParseVHostCombined([]byte(line))
		if err != nil {
			t.Fatalf("%s: parse: %v", line, err)
		}

		if got.Host != want || got.ClientIP != "192.0.2.1" || got.Path != "/a" || got.UserAgent != "ua/1" {
			t.Errorf("%s: host, client, path, user agent = %q, %q, %q, %q; want %q, 192.0.2.1, /a, ua/1", line,
				got.Host, got.ClientIP, got.Path, got.UserAgent, want)
		}
	}
}

// Parses real lines of Debian's other_vhosts_access.log: Apache with three vhosts, one with a path behind Basic auth.
func TestParseVHostCombinedFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/apache_vhost_combined.log")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	want := []struct {
		host, method, path string
		status             int
		size               int64
		referer, userAgent string
	}{
		{"example.com", "GET", "/", 200, 10958, "", "curl/8.14.1"},
		{"example.com", "GET", "/blog/post-1", 200, 205, "https://ref.example/page", "Mozilla/5.0 (X11; Linux x86_64)"},
		{"example.com", "GET", "/missing", 404, 474, "", "Googlebot/2.1 (+http://www.google.com/bot.html)"},
		{"example.com", "HEAD", "/", 200, 255, "", "curl/8.14.1"},
		{"example.com", "POST", "/blog/post-1", 200, 205, "", "curl/8.14.1"},
		{"example.com", "GET", "/blog/post-1", 206, 243, "", "curl/8.14.1"},
		{"example.com", "GET", "/", 200, 10958, "", `ua "quoted" [en]`},
		{"example.com", "GET", "/private/", 200, 233, "", "curl/8.14.1"}, // user "alice smith"
		{"example.com", "GET", "/private/", 401, 703, "", "curl/8.14.1"}, // user "a [b"
		{"example.com", "GET", "/", 200, 13596, "", "curl/8.14.1"},       // port 443
		{"example.org", "GET", "/", 200, 10958, "", "curl/8.14.1"},       // port 8080, logged as 80
	}

	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	if len(lines) != len(want) {
		t.Fatalf("fixture: got %d lines, want %d", len(lines), len(want))
	}

	for i, fields := range want {
		got, err := ParseVHostCombined(lines[i])
		if err != nil {
			t.Fatalf("line %d: %v", i, err)
		}

		if got.ClientIP != "127.0.0.1" || !got.Time.Equal(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)) ||
			!got.HasUserAgent || got.Host != fields.host || got.Method != fields.method || got.Path != fields.path ||
			got.Status != fields.status || got.Size != fields.size || got.Referer != fields.referer ||
			got.UserAgent != fields.userAgent {
			t.Errorf("line %d: %+v; want client 127.0.0.1, 2000-01-01, a user agent, %+v", i, got, fields)
		}
	}
}

// An error names the format and the field; an offset counts from the start of the whole line. An NCSA line's IPv4
// client has no port, whatever its user name.
func TestParseVHostCombinedErrors(t *testing.T) {
	const req = `192.0.2.1 - - [01/Jan/2000:00:00:00 +0000] "GET / HTTP/1.1"`

	const userWithSpace = `192.0.2.1 - alice smith [01/Jan/2000:00:00:00 +0000] "GET / HTTP/1.1" 200 1`

	for _, tc := range []struct{ line, want string }{
		{"", "vhost-combined: vhost is missing at offset 0"},
		{"80 " + req + " 200 1", "vhost-combined: vhost has no port at offset 2"},
		{"example.com", "vhost-combined: vhost has no port at offset 11"},
		{"example.com:65536 " + req + " 200 1", "vhost-combined: vhost has no port at offset 17"},
		{"example.com:http " + req + " 200 1", "vhost-combined: vhost has no port at offset 16"},
		{req + " 200 1", "vhost-combined: vhost has no port at offset 9"},
		{userWithSpace, "vhost-combined: vhost has no port at offset 9"},
		{"example.com:443", "vhost-combined: client is missing at offset 15"},
		{"example.com:443 " + req, "vhost-combined: status is missing at offset 75"},
		{"example.com:443 " + req + " 20x 1", "vhost-combined: status is not a number"},
	} {
		if _, err := ParseVHostCombined([]byte(tc.line)); err == nil || err.Error() != tc.want {
			t.Errorf("ParseVHostCombined(%q): err = %v, want %q", tc.line, err, tc.want)
		}
	}
}
