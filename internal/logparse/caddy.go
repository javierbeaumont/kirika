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
	"strings"
	"time"
)

// The first Unix second of year 10000, past the years Event allows.
const maxTs = 253402300800

// ErrNotAccessLog is returned for an entry of a logger other than an access log, whatever its other fields, and for a
// line that decodes but has no request method, such as a server-startup line.
var ErrNotAccessLog = errors.New("logparse: not a caddy access-log entry")

// The subset of Caddy's JSON access-log schema that kirika consumes.
type caddyLine struct {
	Logger  string `json:"logger"`
	Request struct {
		ClientIP string              `json:"client_ip"`
		Headers  map[string][]string `json:"headers"`
		Host     string              `json:"host"`
		Method   string              `json:"method"`
		RemoteIP string              `json:"remote_ip"`
		URI      string              `json:"uri"`
	} `json:"request"`

	RespHeaders map[string][]string `json:"resp_headers"`
	Size        int64               `json:"size"`
	Status      int                 `json:"status"`
	Ts          float64             `json:"ts"`
}

// ParseCaddyJSON parses a Caddy JSON access-log line into an Event, or returns ErrNotAccessLog.
func ParseCaddyJSON(line []byte) (Event, error) {
	var entry caddyLine

	err := json.Unmarshal(line, &entry) // past a field of the wrong type, it decodes the others
	if !accessLogger(entry.Logger) {
		return Event{}, ErrNotAccessLog
	}

	if err != nil {
		return Event{}, jsonError(err)
	}

	if entry.Request.Method == "" {
		return Event{}, ErrNotAccessLog
	}

	if entry.Ts <= 0 || entry.Ts >= maxTs {
		return Event{}, errors.New("caddy: ts is missing or outside years 1970-9999")
	}

	clientIP := entry.Request.ClientIP
	if clientIP == "" {
		clientIP = entry.Request.RemoteIP
	}

	headers := entry.Request.Headers

	event := Event{
		ClientIP:     clientAddr(clientIP),
		FirstPart:    firstPart(headerFirst(entry.RespHeaders, "Content-Range"), headerFirst(headers, "Range")),
		HasUserAgent: headers != nil,
		Host:         VHost(entry.Request.Host),
		Method:       entry.Request.Method,
		Path:         unreserved(stripQuery(entry.Request.URI)),
		Referer:      headerFirst(headers, "Referer"),
		Size:         entry.Size,
		Status:       entry.Status,
		Time:         unixFloat(entry.Ts),
		UserAgent:    headerFirst(headers, "User-Agent"),
	}
	if err := event.check(); err != nil {
		return Event{}, fmt.Errorf("caddy: %w", err)
	}

	return event, nil
}

// Returns the error of a line that does not decode. A field below a header map is named by the map, since the client
// chose the header's name.
func jsonError(err error) error {
	var typeErr *json.UnmarshalTypeError
	if !errors.As(err, &typeErr) {
		return errors.New("caddy: not JSON")
	}

	if typeErr.Field == "" {
		return errors.New("caddy: not a JSON object")
	}

	f := strings.SplitN(typeErr.Field, ".", 3)
	if f[0] != "request" || len(f) == 1 {
		return fmt.Errorf("caddy: %s has the wrong type", f[0])
	}

	return fmt.Errorf("caddy: %s.%s has the wrong type", f[0], f[1])
}

// Reports whether a Caddy logger writes access entries. Caddy names an access log http.log.access or
// http.log.access.NAME; an empty name counts as one.
func accessLogger(name string) bool {
	return name == "" || name == "http.log.access" || strings.HasPrefix(name, "http.log.access.")
}

// Reports whether a range starts at byte 0: the one a Content-Range response header sent ("bytes 0-99/100") or, without
// it, the first one a Range request header asked for ("bytes=0-99"). A range unit ignores case.
func firstPart(sent, asked string) bool {
	if sent != "" {
		return strings.HasPrefix(strings.ToLower(sent), "bytes 0-")
	}

	return strings.HasPrefix(strings.ToLower(asked), "bytes=0-")
}

// Returns the first value of a header, matching its name in any case. When several spellings carry values, the one that
// sorts first wins, so the result does not depend on map order.
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

// Returns the request target with any "?query" removed.
func stripQuery(uri string) string {
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		return uri[:i]
	}

	return uri
}

// Converts Caddy's fractional-seconds timestamp to a UTC time.
func unixFloat(ts float64) time.Time {
	sec := int64(ts)
	nsec := int64((ts - float64(sec)) * 1e9)

	return time.Unix(sec, nsec).UTC()
}
