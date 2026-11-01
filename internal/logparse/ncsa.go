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
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ncsaTime is the NCSA/CLF timestamp layout, e.g. 03/Jul/2026:13:55:36 +0000.
const ncsaTime = "02/Jan/2006:15:04:05 -0700"

// ParseNCSA parses one line of NCSA Common or Combined Log Format, as emitted by Apache, nginx (default), Lighttpd, and
// OpenLiteSpeed:
//
//	host ident authuser [time] "request" status bytes ["referer" "user-agent"]
//
// The last two quoted fields (Combined) are optional, and fields after them are ignored. NCSA lines carry the client
// host but no vhost, so Event.Host is left empty for the caller to fill.
func ParseNCSA(line []byte) (Event, error) {
	sc := &clfScanner{s: string(line)}
	host := sc.plain()
	sc.plain() // ident (ignored)
	sc.plain() // authuser (ignored)
	ts := sc.bracket()

	req, ok := sc.quote()
	if !ok {
		sc.fail("expected quoted request")
	}

	status := sc.plain()
	size := sc.plain()
	ref, _ := sc.quote() // Combined only
	ua, _ := sc.quote()  // Combined only

	if sc.err != nil {
		return Event{}, fmt.Errorf("ncsa: %w", sc.err)
	}

	// NCSA logs a literal "-" for an absent referer/user-agent.
	if ref == "-" {
		ref = ""
	}

	if ua == "-" {
		ua = ""
	}

	t, err := time.Parse(ncsaTime, ts)
	if err != nil {
		return Event{}, fmt.Errorf("ncsa: bad time %q: %w", ts, err)
	}

	method, uri, proto := splitRequest(req)

	ev := Event{
		ClientIP:  host,
		Method:    method,
		Path:      stripQuery(uri),
		Proto:     proto,
		Referer:   ref,
		Time:      t.UTC(),
		URI:       uri,
		UserAgent: ua,
	}

	if size != "-" {
		n, err := strconv.ParseUint(size, 10, 63)
		if err != nil {
			return Event{}, fmt.Errorf("ncsa: bad size %q: %w", size, err)
		}

		ev.Size = int64(n)
	}

	if status != "-" {
		n, err := strconv.ParseUint(status, 10, 16)
		if err != nil {
			return Event{}, fmt.Errorf("ncsa: bad status %q: %w", status, err)
		}

		ev.Status = int(n)
	}

	if err := ev.check(); err != nil {
		return Event{}, fmt.Errorf("ncsa: %w", err)
	}

	return ev, nil
}

// clfScanner walks a CLF line field by field.
type clfScanner struct {
	err error
	i   int
	s   string
}

// bracket reads a [...] field (its contents may include spaces).
func (sc *clfScanner) bracket() string {
	if sc.err != nil {
		return ""
	}

	sc.skipSpaces()

	if sc.i >= len(sc.s) || sc.s[sc.i] != '[' {
		sc.fail("expected [")
		return ""
	}

	sc.i++

	start := sc.i
	for sc.i < len(sc.s) && sc.s[sc.i] != ']' {
		sc.i++
	}

	if sc.i >= len(sc.s) {
		sc.fail("unterminated [")
		return ""
	}

	val := sc.s[start:sc.i]
	sc.i++ // consume ']'

	return val
}

func (sc *clfScanner) fail(msg string) {
	if sc.err == nil {
		sc.err = fmt.Errorf("%s at offset %d", msg, sc.i)
	}
}

// plain reads a space-delimited field.
func (sc *clfScanner) plain() string {
	if sc.err != nil {
		return ""
	}

	sc.skipSpaces()

	start := sc.i
	for sc.i < len(sc.s) && sc.s[sc.i] != ' ' {
		sc.i++
	}

	if sc.i == start {
		sc.fail("expected field")
	}

	return sc.s[start:sc.i]
}

// quote reads a "..." field and decodes its escapes: \xHH is the byte HH (how Apache and nginx log non-printable
// bytes), and a backslash before any other byte yields that byte. ok is false when the next field is not a quote (a
// Common-format line has no referer/user-agent).
func (sc *clfScanner) quote() (string, bool) {
	if sc.err != nil {
		return "", false
	}

	sc.skipSpaces()

	if sc.i >= len(sc.s) || sc.s[sc.i] != '"' {
		return "", false
	}

	sc.i++

	var b strings.Builder

	for sc.i < len(sc.s) {
		c := sc.s[sc.i]
		switch {
		case c == '\\' && sc.i+3 < len(sc.s) && sc.s[sc.i+1] == 'x' && isHex(sc.s[sc.i+2]) && isHex(sc.s[sc.i+3]):
			b.WriteByte(unhex(sc.s[sc.i+2])<<4 | unhex(sc.s[sc.i+3]))

			sc.i += 4
		case c == '\\' && sc.i+1 < len(sc.s):
			b.WriteByte(sc.s[sc.i+1])
			sc.i += 2
		case c == '"':
			sc.i++
			return b.String(), true
		default:
			b.WriteByte(c)

			sc.i++
		}
	}

	sc.fail("unterminated quote")

	return "", false
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c >= 'a':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

func (sc *clfScanner) skipSpaces() {
	for sc.i < len(sc.s) && sc.s[sc.i] == ' ' {
		sc.i++
	}
}

// splitRequest splits a request line ("GET /path HTTP/1.1") into its parts, tolerating missing protocol (HTTP/0.9) or a
// blank request.
func splitRequest(req string) (method, uri, proto string) {
	f := strings.Fields(req)
	if len(f) > 0 {
		method = f[0]
	}

	if len(f) > 1 {
		uri = f[1]
	}

	if len(f) > 2 {
		proto = f[2]
	}

	return
}
