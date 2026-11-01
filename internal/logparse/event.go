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
	"fmt"
	"time"
)

// Event is one normalized access-log record. Fields kirika does not use are dropped.
type Event struct {
	ClientIP  string    // client address
	Host      string    // vhost, port stripped (e.g. "example.com")
	Method    string    // HTTP method (GET, POST, ...)
	Path      string    // URI with the query string removed
	Proto     string    // e.g. "HTTP/1.1"
	Referer   string    // Referer header
	Size      int64     // response body size in bytes, never negative
	Status    int       // HTTP status code, 100-999, or 0 when the log has none
	Time      time.Time // request time, UTC, in years 1-9999
	URI       string    // raw request target, query string included
	UserAgent string    // User-Agent header
}

// check returns an error for a field outside the range Event documents.
func (ev Event) check() error {
	switch {
	case ev.Size < 0:
		return fmt.Errorf("negative size %d", ev.Size)
	case ev.Status != 0 && (ev.Status < 100 || ev.Status > 999):
		return fmt.Errorf("status %d is not a three-digit code", ev.Status)
	case ev.Time.Year() < 1 || ev.Time.Year() > 9999:
		return fmt.Errorf("time %s is outside years 1-9999", ev.Time)
	}

	return nil
}
