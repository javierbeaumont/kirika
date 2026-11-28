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
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// The NCSA/CLF timestamp layout, e.g. 01/Jan/2000:00:00:00 +0000.
const ncsaTime = "02/Jan/2006:15:04:05 -0700"

// ParseNCSA parses one line of NCSA Common or Combined Log Format, as emitted by Apache, nginx (default), Lighttpd, and
// OpenLiteSpeed:
//
//	client ident authuser [time] "request" status size ["referer" "user-agent"]
//
// The last two quoted fields (Combined) are optional, and fields after them are ignored. NCSA lines carry no vhost, so
// Event.Host is left empty for the caller to fill.
func ParseNCSA(line []byte) (Event, error) {
	event, err := parseCLF(&clfScanner{s: string(line)})
	if err != nil {
		return Event{}, fmt.Errorf("ncsa: %w", err)
	}

	return event, nil
}

// ParseVHostCombined parses one line of Apache's vhost_combined format, that of Debian's other_vhosts_access.log: the
// vhost's name and canonical port, then a line ParseNCSA reads.
//
//	vhost:port client ident authuser [time] "request" status size ["referer" "user-agent"]
//
// Event.Host is the vhost, as VHost returns it. A first field with no port, as an NCSA line's IPv4 or named client, is
// an error.
func ParseVHostCombined(line []byte) (Event, error) {
	scanner := &clfScanner{s: string(line)}

	host, hasPort := vhostHost(scanner.plain("vhost"))
	if !hasPort {
		scanner.fail("vhost", "has no port")
	}

	event, err := parseCLF(scanner)
	if err != nil {
		return Event{}, fmt.Errorf("vhost-combined: %w", err)
	}

	event.Host = host

	return event, nil
}

// Returns the vhost of a %v:%p field as VHost returns it, and false without a numeric port. The port follows the last
// colon, as %v may be an IPv6 address without brackets.
func vhostHost(field string) (host string, hasPort bool) {
	colon := strings.LastIndexByte(field, ':')
	if colon < 0 {
		return "", false
	}

	port := field[colon+1:]
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return "", false
	}

	return VHost(net.JoinHostPort(unbracket(field[:colon]), port)), true
}

// Parses a Common or Combined line from where scanner stands.
func parseCLF(scanner *clfScanner) (Event, error) {
	client := scanner.plain("client")
	scanner.plain("ident")
	scanner.untilTime("authuser")
	timestamp := scanner.bracket("time")

	request, ok := scanner.quote("request")
	if !ok {
		scanner.fail("request", "is not quoted")
	}

	status := scanner.plain("status")
	size := scanner.plain("size")
	referer, _ := scanner.quote("referer")
	userAgent, hasUserAgent := scanner.quote("user agent")

	if scanner.err != nil {
		return Event{}, scanner.err
	}

	// NCSA logs a literal "-" for an absent referer/user-agent.
	if referer == "-" {
		referer = ""
	}

	if userAgent == "-" {
		userAgent = ""
	}

	requestTime, err := parseNCSATime(timestamp)
	if err != nil {
		return Event{}, errors.New("time is invalid")
	}

	method, target := splitRequest(request)

	event := Event{
		ClientIP:     clientAddr(client),
		HasUserAgent: hasUserAgent,
		Method:       method,
		Path:         stripQuery(target),
		Referer:      referer,
		Time:         requestTime.UTC(),
		UserAgent:    userAgent,
	}

	if size != "-" {
		bytes, err := strconv.ParseUint(size, 10, 63)
		if err != nil {
			return Event{}, numberError("size", err)
		}

		event.Size = int64(bytes)
	}

	if status != "-" {
		code, err := strconv.ParseUint(status, 10, 16)
		if err != nil {
			return Event{}, numberError("status", err)
		}

		event.Status = int(code)
	}

	if err := event.check(); err != nil {
		return Event{}, err
	}

	return event, nil
}

// Reads an NCSA timestamp. A leap second (second 60) reads as second 59, since time.Parse refuses it.
func parseNCSATime(timestamp string) (time.Time, error) {
	dateTime, zone, _ := strings.Cut(timestamp, " ")
	if upToMinute, isLeap := strings.CutSuffix(dateTime, ":60"); isLeap {
		timestamp = upToMinute + ":59 " + zone
	}

	return time.Parse(ncsaTime, timestamp)
}

// Returns the error of a numeric field that does not parse.
func numberError(field string, err error) error {
	if errors.Is(err, strconv.ErrRange) {
		return fmt.Errorf("%s is out of range", field)
	}

	return fmt.Errorf("%s is not a number", field)
}

// A scanner that walks a CLF line field by field.
type clfScanner struct {
	err error
	i   int
	s   string
}

// Reads a [...] field (its contents may include spaces).
func (sc *clfScanner) bracket(field string) string {
	if sc.err != nil {
		return ""
	}

	sc.skipSpaces()

	if sc.i >= len(sc.s) || sc.s[sc.i] != '[' {
		sc.fail(field, "does not start with [")
		return ""
	}

	sc.i++

	start := sc.i
	for sc.i < len(sc.s) && sc.s[sc.i] != ']' {
		sc.i++
	}

	if sc.i >= len(sc.s) {
		sc.fail(field, "has no closing ]")
		return ""
	}

	value := sc.s[start:sc.i]
	sc.i++

	return value
}

// Stops the scan at its first error, which names the field and the current offset.
func (sc *clfScanner) fail(field, problem string) {
	if sc.err == nil {
		sc.err = fmt.Errorf("%s %s at offset %d", field, problem, sc.i)
	}
}

// Reads a space-delimited field.
func (sc *clfScanner) plain(field string) string {
	if sc.err != nil {
		return ""
	}

	sc.skipSpaces()

	start := sc.i
	for sc.i < len(sc.s) && sc.s[sc.i] != ' ' {
		sc.i++
	}

	if sc.i == start {
		sc.fail(field, "is missing")
	}

	return sc.s[start:sc.i]
}

// Reads the user name, which may hold spaces and brackets: it runs to the last " [" before the time's end, else to the
// end of the line.
func (sc *clfScanner) untilTime(field string) string {
	if sc.err != nil {
		return ""
	}

	sc.skipSpaces()

	start := sc.i
	rest := sc.s[start:]

	if timeStart := strings.LastIndex(rest[:timeEnd(rest)], " ["); timeStart >= 0 {
		sc.i += timeStart
	} else {
		sc.i = len(sc.s)
	}

	if sc.i == start {
		sc.fail(field, "is missing")
	}

	return sc.s[start:sc.i]
}

// Returns the index in rest of the time's end, the first "]" followed, past any spaces, by a quote, or len(rest)
// without one. A server escapes a quote in a user name, so no "]" in one is followed by a quote.
func timeEnd(rest string) int {
	for i := range len(rest) {
		if rest[i] == ']' && strings.HasPrefix(strings.TrimLeft(rest[i+1:], " "), `"`) {
			return i
		}
	}

	return len(rest)
}

// Reads a "..." field and decodes its escapes: \xHH is the byte HH (how Apache and nginx log non-printable bytes),
// \u00HH the character U+00HH (how nginx's escape=json logs a control character), and unescape decodes any other.
// quoted is false on an error or when no quoted field follows (a Common-format line has no referer/user-agent).
func (sc *clfScanner) quote(field string) (value string, quoted bool) {
	if sc.err != nil {
		return "", false
	}

	sc.skipSpaces()

	if sc.i >= len(sc.s) || sc.s[sc.i] != '"' {
		return "", false
	}

	sc.i++

	var decoded strings.Builder

	for sc.i < len(sc.s) {
		char := sc.s[sc.i]
		switch {
		case char == '\\' && sc.i+3 < len(sc.s) && sc.s[sc.i+1] == 'x' && isHex(sc.s[sc.i+2]) && isHex(sc.s[sc.i+3]):
			decoded.WriteByte(unhex(sc.s[sc.i+2])<<4 | unhex(sc.s[sc.i+3]))

			sc.i += 4
		case char == '\\' && sc.i+5 < len(sc.s) && sc.s[sc.i+1:sc.i+4] == "u00" && isHex(sc.s[sc.i+4]) &&
			isHex(sc.s[sc.i+5]):
			decoded.WriteRune(rune(unhex(sc.s[sc.i+4])<<4 | unhex(sc.s[sc.i+5])))

			sc.i += 6
		case char == '\\' && sc.i+1 < len(sc.s):
			decoded.WriteByte(unescape(sc.s[sc.i+1]))
			sc.i += 2
		case char == '"':
			sc.i++
			return decoded.String(), true
		default:
			decoded.WriteByte(char)

			sc.i++
		}
	}

	sc.fail(field, "has no closing quote")

	return "", false
}

// Returns the byte a backslash before char stands for: the control character of a C escape, as Apache, lighttpd or
// nginx's escape=json writes one, or else char.
func unescape(char byte) byte {
	switch char {
	case 'a':
		return '\a'
	case 'b':
		return '\b'
	case 'f':
		return '\f'
	case 'n':
		return '\n'
	case 'r':
		return '\r'
	case 't':
		return '\t'
	case 'v':
		return '\v'
	default:
		return char
	}
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

// The whitespace that RFC 9112, section 3, lets a recipient treat as a request line's separator: a space, a tab, a
// vertical tab, a form feed or a carriage return.
const requestSpace = " \t\v\f\r"

// Splits a request line ("GET /path HTTP/1.1") at runs of requestSpace into its method and target, each empty when
// missing.
func splitRequest(request string) (method, target string) {
	method, rest := cutWord(request)
	target, _ = cutWord(rest)

	return method, target
}

// Returns the first word of text, without the requestSpace before it, and what follows it.
func cutWord(text string) (word, rest string) {
	text = strings.TrimLeft(text, requestSpace)
	if end := strings.IndexAny(text, requestSpace); end >= 0 {
		return text[:end], text[end:]
	}

	return text, ""
}
