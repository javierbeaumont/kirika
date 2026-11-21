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
	"strconv"
	"strings"
	"time"
)

// Event is one normalized access-log record. Fields kirika does not use are dropped.
type Event struct {
	ClientIP     string    // client address, without a port
	FirstPart    bool      // the range sent, or else the first one asked for, starts at byte 0
	HasUserAgent bool      // the log carries a User-Agent, empty or not
	Host         string    // vhost as VHost returns it
	Method       string    // HTTP method (GET, POST, ...)
	Path         string    // URI without its query string, with unreserved characters decoded
	Referer      string    // Referer header
	Size         int64     // response size in bytes as the log counts it, never negative
	Status       int       // HTTP status code, 100-999, or 0 when the log has none
	Time         time.Time // request time, UTC, in years 1-9999
	UserAgent    string    // User-Agent header
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

// VHost returns a host without a name's final dot and without an empty or default port, 80 or 443. Any other port
// stays, since it usually serves another site, and a valid one loses its leading zeros. An IPv6 address left without a
// port loses its brackets.
func VHost(host string) string {
	name, port, err := net.SplitHostPort(host)
	if err != nil {
		return unbracket(strings.TrimSuffix(host, "."))
	}

	name = strings.TrimSuffix(name, ".")
	portNumber, err := strconv.ParseUint(port, 10, 16)

	switch {
	case port == "" || err == nil && (portNumber == 80 || portNumber == 443):
		return name
	case err == nil:
		return net.JoinHostPort(name, strconv.FormatUint(portNumber, 10))
	default:
		return net.JoinHostPort(name, port)
	}
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
