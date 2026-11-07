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

package kvstore

import (
	"bytes"
	"encoding/binary"
	"math"
	"strings"
	"testing"
)

// A day key gives its host and month, whether the host's length takes one byte of it or two. A key of another shape is
// refused.
func TestSplitDay(t *testing.T) {
	day := len(encKey(tagDay))
	date := base.Format("20060102")

	for _, host := range []string{"h", strings.Repeat("h", 200)} {
		name, month, ok := splitDay(timeKey(tagDay, host, date)[day:])
		if want := base.Format("2006-01"); !ok || name != host || month != want {
			t.Errorf("splitDay of %.10q... = %.10q..., %q, %v; want %q", host, name, month, ok, want)
		}
	}

	good := timeKey(tagDay, "h", date)[day:]

	for name, rest := range map[string][]byte{
		"cut length":     bytes.Repeat([]byte{0x80}, 8),
		"wrapped length": binary.AppendUvarint(nil, math.MaxUint64-7),
		"long date":      append(bytes.Clone(good), '0'),
	} {
		if _, _, ok := splitDay(rest); ok {
			t.Errorf("%s %q: split", name, rest)
		}
	}
}
