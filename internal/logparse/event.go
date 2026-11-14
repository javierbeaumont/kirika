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

// Package logparse turns web-server access-log lines into a normalized Event. Each supported log format has its own
// parser.
package logparse

import (
	"errors"
	"net"
	"strings"
	"time"
)

// Event is one normalized access-log record. Fields kirika does not use are dropped.
type Event struct {
	ClientIP  string    // client address, without a port
	FirstPart bool      // a partial response known to start at byte 0
	Host      string    // vhost, without port 80 or 443 (e.g. "example.com", "example.com:8080")
	Method    string    // HTTP method (GET, POST, ...)
	Path      string    // URI without its query string, with unreserved characters decoded
	Proto     string    // e.g. "HTTP/1.1"
	Referer   string    // Referer header
	Size      int64     // response body size in bytes, never negative
	Status    int       // HTTP status code, 100-999, or 0 when the log has none
	Time      time.Time // request time, UTC, in years 1-9999
	URI       string    // raw request target, query string included
	UserAgent string    // User-Agent header
}

// Returns an error for a field outside the range Event documents.
func (ev Event) check() error {
	switch {
	case ev.Size < 0:
		return errors.New("size is negative")
	case ev.Status != 0 && (ev.Status < 100 || ev.Status > 999):
		return errors.New("status is not a three-digit code")
	case ev.Time.Year() < 1 || ev.Time.Year() > 9999:
		return errors.New("time is outside years 1-9999")
	}

	return nil
}

// Returns a client address without its port, which changes with each connection, and an IPv6 address without its
// brackets.
func clientAddr(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}

	return unbracket(addr)
}

// Returns an IPv6 address written as "[addr]" without its brackets.
func unbracket(s string) string {
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return s[1 : len(s)-1]
	}

	return s
}

// Decodes the percent-encoded unreserved characters of a path: letters, digits and "-._~" mean the same either way (RFC
// 3986, section 2.3). Any other escape stays as written.
func unreserved(path string) string {
	if !strings.Contains(path, "%") {
		return path
	}

	var b strings.Builder

	for i := 0; i < len(path); i++ {
		if path[i] == '%' && i+2 < len(path) && isHex(path[i+1]) && isHex(path[i+2]) {
			if c := unhex(path[i+1])<<4 | unhex(path[i+2]); isUnreserved(c) {
				b.WriteByte(c)

				i += 2

				continue
			}
		}

		b.WriteByte(path[i])
	}

	return b.String()
}

func isUnreserved(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || strings.IndexByte("-._~", c) >= 0
}
