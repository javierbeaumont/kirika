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

package kvstore

import (
	"time"

	"github.com/javierbeaumont/kirika/internal/logparse"
)

// The one date the tests write; every other instant is an offset from it.
var base = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)

const (
	botUA     = "Googlebot/2.1"
	desktopUA = "Mozilla/5.0 (X11; Linux x86_64)"
	mobileUA  = "Mozilla/5.0 (iPhone)"
)

// Returns hour h of day d of January 2000.
func at(d, h int) time.Time {
	return base.AddDate(0, 0, d-1).Add(time.Duration(h) * time.Hour)
}

// Returns a request of host for path from a desktop browser, answered with status and size at t.
func page(host, path string, status int, size int64, t time.Time) logparse.Event {
	return logparse.Event{Host: host, Path: path, Status: status, Size: size, Time: t, UserAgent: desktopUA}
}

// Returns the counters of n page hits of size bytes in all.
func pageCounts(n, size int64) Counts {
	return Counts{HitBandwidth: size, Hits: n, PageBandwidth: size, Pages: n}
}
