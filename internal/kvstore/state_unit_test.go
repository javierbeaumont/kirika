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
	"math"
	"testing"
)

func TestStateCodec(t *testing.T) {
	for _, s := range []LogState{
		{},
		{Line: -1, Offset: -1, Sum: [8]byte{1}},
		{Line: 7, Offset: 300},
		{Line: math.MaxInt64, Offset: math.MaxInt64, Sum: [8]byte{0xff, 0, 0, 0, 0, 0, 0, 0xff}},
	} {
		if got, ok := decodeState(encodeState(s)); !ok || got != s {
			t.Errorf("round trip of %+v = %+v, %v", s, got, ok)
		}
	}

	good := encodeState(LogState{Line: 7, Offset: 300, Sum: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}})

	for name, b := range map[string][]byte{
		"empty":          {},
		"version 0":      append([]byte{0}, good[1:]...),
		"cut line":       append([]byte{stateVersion}, bytes.Repeat([]byte{0x80}, 8)...),
		"line overflow":  append([]byte{stateVersion}, bytes.Repeat([]byte{0xff}, 11)...),
		"cut offset":     append([]byte{stateVersion, good[1]}, bytes.Repeat([]byte{0x80}, 8)...),
		"no offset":      append([]byte{stateVersion, good[1]}, good[len(good)-8:]...),
		"short checksum": good[:len(good)-1],
		"trailing byte":  append(bytes.Clone(good), 0),
	} {
		if _, ok := decodeState(b); ok {
			t.Errorf("%s %x: decoded", name, b)
		}
	}
}
