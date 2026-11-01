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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// maxTs is the first Unix second of year 10000, past the years Event allows.
const maxTs = 253402300800

// ErrNotAccessLog is returned when a line is valid JSON but not a Caddy access entry (for example a server-startup log
// line in a mixed log stream).
var ErrNotAccessLog = errors.New("logparse: not a caddy access-log entry")

// caddyLine mirrors the subset of Caddy's JSON access-log schema that kirika consumes. Unknown fields are ignored by
// encoding/json.
type caddyLine struct {
	Request struct {
		ClientIP string              `json:"client_ip"`
		Headers  map[string][]string `json:"headers"`
		Host     string              `json:"host"`
		Method   string              `json:"method"`
		Proto    string              `json:"proto"`
		RemoteIP string              `json:"remote_ip"`
		URI      string              `json:"uri"`
	} `json:"request"`

	Size   int64   `json:"size"`
	Status int     `json:"status"`
	Ts     float64 `json:"ts"`
}

// ParseCaddyJSON parses a single Caddy JSON access-log line into an Event. It returns ErrNotAccessLog for well-formed
// JSON that is not a request entry.
func ParseCaddyJSON(line []byte) (Event, error) {
	var c caddyLine
	if err := json.Unmarshal(line, &c); err != nil {
		return Event{}, fmt.Errorf("caddy: %w", err)
	}

	if c.Request.Method == "" {
		return Event{}, ErrNotAccessLog
	}

	if c.Ts <= 0 || c.Ts >= maxTs {
		return Event{}, fmt.Errorf("caddy: ts %v is missing or outside years 1970-9999", c.Ts)
	}

	clientIP := c.Request.ClientIP
	if clientIP == "" {
		clientIP = c.Request.RemoteIP
	}

	ev := Event{
		ClientIP:  clientIP,
		Host:      stripPort(c.Request.Host),
		Method:    c.Request.Method,
		Path:      stripQuery(c.Request.URI),
		Proto:     c.Request.Proto,
		Referer:   headerFirst(c.Request.Headers, "Referer"),
		Size:      c.Size,
		Status:    c.Status,
		Time:      unixFloat(c.Ts),
		URI:       c.Request.URI,
		UserAgent: headerFirst(c.Request.Headers, "User-Agent"),
	}
	if err := ev.check(); err != nil {
		return Event{}, fmt.Errorf("caddy: %w", err)
	}

	return ev, nil
}

// headerFirst returns the first value of a header, matching its name in any case. When several spellings carry values,
// the one that sorts first wins, so the result does not depend on map order.
func headerFirst(h map[string][]string, name string) string {
	key := ""

	for k, v := range h {
		if len(v) > 0 && strings.EqualFold(k, name) && (key == "" || k < key) {
			key = k
		}
	}

	if key == "" {
		return ""
	}

	return h[key][0]
}

// stripPort returns the bare hostname of a Host header: without its ":port" suffix, and an IPv6 address without its
// brackets.
func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host[1 : len(host)-1]
	}

	return host
}

// stripQuery returns the request target with any "?query" removed.
func stripQuery(uri string) string {
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		return uri[:i]
	}

	return uri
}

// unixFloat converts Caddy's fractional-seconds timestamp to a UTC time.
func unixFloat(ts float64) time.Time {
	sec := int64(ts)
	nsec := int64((ts - float64(sec)) * 1e9)

	return time.Unix(sec, nsec).UTC()
}
