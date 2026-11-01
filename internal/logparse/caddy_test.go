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
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

// caddyRequestLine is a minimal Caddy access-log line; %s takes extra JSON request fields.
const caddyRequestLine = `{"ts":1783082721.25,"request":{"method":"GET","uri":"/",%s},"status":200,"size":1}`

func caddyRequest(fields string) []byte {
	return []byte(fmt.Sprintf(caddyRequestLine, fields))
}

// caddyEntry is a Caddy request entry with the given ts, status and size, as raw JSON values.
func caddyEntry(ts, status, size string) []byte {
	return []byte(fmt.Sprintf(`{"ts":%s,"request":{"method":"GET","uri":"/"},"status":%s,"size":%s}`, ts, status, size))
}

func TestParseCaddyJSONClientIP(t *testing.T) {
	for _, tc := range []struct{ fields, want string }{
		{`"client_ip":"198.51.100.7","remote_ip":"192.0.2.1"`, "198.51.100.7"},
		{`"remote_ip":"192.0.2.1"`, "192.0.2.1"},
		{`"proto":"HTTP/1.1"`, ""},
	} {
		got, err := ParseCaddyJSON(caddyRequest(tc.fields))
		if err != nil {
			t.Fatalf("%s: parse: %v", tc.fields, err)
		}

		if got.ClientIP != tc.want {
			t.Errorf("%s: ClientIP = %q, want %q", tc.fields, got.ClientIP, tc.want)
		}
	}
}

func TestParseCaddyJSONErrors(t *testing.T) {
	for _, line := range [][]byte{
		nil,
		[]byte("not json"),
		caddyEntry(`"1783082721"`, "200", "1"),
		caddyEntry("1783082721", `"200"`, "1"),
		caddyEntry("1783082721", "200", `"1"`),
		caddyEntry("1783082721", "200.5", "1"),
		caddyEntry("1783082721", "200", "-1"),
		caddyEntry("1783082721", "-200", "1"),
		caddyEntry("1783082721", "99", "1"),
		caddyEntry("1783082721", "1000", "1"),
		caddyEntry("0", "200", "1"),
		caddyEntry("-1", "200", "1"),
		caddyEntry("253402300800", "200", "1"),
		caddyEntry("1e30", "200", "1"),
		[]byte(`{"request":{"method":"GET","uri":"/"},"status":200,"size":1}`),
	} {
		if _, err := ParseCaddyJSON(line); err == nil || errors.Is(err, ErrNotAccessLog) {
			t.Errorf("ParseCaddyJSON(%s): err = %v, want a parse error", line, err)
		}
	}
}

func TestParseCaddyJSONNotAccessLog(t *testing.T) {
	for _, line := range []string{`{}`, `null`, `{"level":"info","msg":"serving initial configuration"}`} {
		if _, err := ParseCaddyJSON([]byte(line)); !errors.Is(err, ErrNotAccessLog) {
			t.Errorf("ParseCaddyJSON(%s): err = %v, want ErrNotAccessLog", line, err)
		}
	}
}

// TestParseCaddyJSONFixture parses real Caddy access-log lines (testdata/caddy_access.jsonl).
func TestParseCaddyJSONFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/caddy_access.jsonl")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	if len(lines) != 3 {
		t.Fatalf("fixture: got %d lines, want 3", len(lines))
	}

	events := make([]Event, len(lines))
	for i, l := range lines {
		ev, err := ParseCaddyJSON(l)
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

		if ev.Host != "localhost" {
			t.Errorf("line %d: Host = %q, want localhost", i, ev.Host)
		}

		if ev.Proto != "HTTP/1.1" {
			t.Errorf("line %d: Proto = %q, want HTTP/1.1", i, ev.Proto)
		}

		if ev.Size != 33 {
			t.Errorf("line %d: Size = %d, want 33", i, ev.Size)
		}

		if ev.Status != 200 {
			t.Errorf("line %d: Status = %d, want 200", i, ev.Status)
		}

		if ev.Time.Year() != 2026 {
			t.Errorf("line %d: Time.Year() = %d, want 2026", i, ev.Time.Year())
		}
	}

	// Line 0: GET / with curl UA, no referer.
	if got := events[0]; got.Method != "GET" || got.Path != "/" || got.Referer != "" || got.URI != "/" ||
		got.UserAgent != "curl/8.7.1" {
		t.Errorf("line 0 mismatch: %+v", got)
	}

	// Line 1: GET with query string, custom UA and a referer.
	if got := events[1]; got.Method != "GET" || got.Path != "/blog/post-1" ||
		got.Referer != "https://ref.example/page" || got.URI != "/blog/post-1?utm=x" ||
		got.UserAgent != "kirika-test-agent/1.0" {
		t.Errorf("line 1 mismatch: %+v", got)
	}

	// Line 2: POST /api/submit.
	if got := events[2]; got.Method != "POST" || got.Path != "/api/submit" {
		t.Errorf("line 2 mismatch: %+v", got)
	}
}

func TestParseCaddyJSONHeaders(t *testing.T) {
	for _, tc := range []struct{ headers, referer, ua string }{
		{`{"Referer":["https://a.example/","https://b.example/"],"User-Agent":["ua/1"]}`, "https://a.example/", "ua/1"},
		{`{"referer":["https://ref.example/"],"user-agent":["ua/1.0"]}`, "https://ref.example/", "ua/1.0"},
		{`{"Referer":["https://upper.example/"],"referer":["https://lower.example/"]}`, "https://upper.example/", ""},
		{`{"Referer":[],"referer":["https://lower.example/"]}`, "https://lower.example/", ""},
		{`{"Accept":["*/*"]}`, "", ""},
	} {
		got, err := ParseCaddyJSON(caddyRequest(`"headers":` + tc.headers))
		if err != nil {
			t.Fatalf("%s: parse: %v", tc.headers, err)
		}

		if got.Referer != tc.referer || got.UserAgent != tc.ua {
			t.Errorf("%s: referer/ua = %q/%q, want %q/%q", tc.headers, got.Referer, got.UserAgent, tc.referer, tc.ua)
		}
	}
}

func TestParseCaddyJSONHost(t *testing.T) {
	for _, tc := range []struct{ host, want string }{
		{"", ""},
		{"::1", "::1"},
		{"[::1]", "::1"},
		{"[::1]:8080", "::1"},
		{"example.com", "example.com"},
		{"example.com:8443", "example.com"},
	} {
		got, err := ParseCaddyJSON(caddyRequest(fmt.Sprintf(`"host":%q`, tc.host)))
		if err != nil {
			t.Fatalf("host %q: parse: %v", tc.host, err)
		}

		if got.Host != tc.want {
			t.Errorf("host %q: Host = %q, want %q", tc.host, got.Host, tc.want)
		}
	}
}

func TestParseCaddyJSONPath(t *testing.T) {
	for _, tc := range []struct{ uri, want string }{
		{"*", "*"},
		{"/a/b", "/a/b"},
		{"/a?b=c?d", "/a"},
		{"?x", ""},
	} {
		line := fmt.Sprintf(`{"ts":1783082721,"request":{"method":"GET","uri":%q},"status":200,"size":1}`, tc.uri)

		got, err := ParseCaddyJSON([]byte(line))
		if err != nil {
			t.Fatalf("uri %q: parse: %v", tc.uri, err)
		}

		if got.Path != tc.want || got.URI != tc.uri {
			t.Errorf("uri %q: Path/URI = %q/%q, want %q/%q", tc.uri, got.Path, got.URI, tc.want, tc.uri)
		}
	}
}

// TestParseCaddyJSONRanges accepts the bounds of every checked field.
func TestParseCaddyJSONRanges(t *testing.T) {
	for _, tc := range []struct {
		ts, status, size string
		wantStatus       int
		wantSize         int64
	}{
		{"1783082721", "0", "0", 0, 0},
		{"1783082721", "100", "9223372036854775807", 100, 9223372036854775807},
		{"253402300799", "999", "1", 999, 1},
	} {
		got, err := ParseCaddyJSON(caddyEntry(tc.ts, tc.status, tc.size))
		if err != nil {
			t.Fatalf("ts %s, status %s, size %s: parse: %v", tc.ts, tc.status, tc.size, err)
		}

		if got.Status != tc.wantStatus || got.Size != tc.wantSize {
			t.Errorf("status/size = %d/%d, want %d/%d", got.Status, got.Size, tc.wantStatus, tc.wantSize)
		}
	}
}

func TestParseCaddyJSONTime(t *testing.T) {
	got, err := ParseCaddyJSON(caddyRequest(`"remote_ip":"192.0.2.1"`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if want := time.Unix(1783082721, 250000000).UTC(); !got.Time.Equal(want) || got.Time.Location() != time.UTC {
		t.Errorf("Time = %v, want %v", got.Time, want)
	}
}
