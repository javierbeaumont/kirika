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
	"testing"
)

func TestSessionCodec(t *testing.T) {
	for _, s := range []session{
		{},
		{class: newClass(true, groupCorrect), exit: "/b", host: "h", last: -62135596800},
		{last: 1 << 40},
	} {
		if got, ok := decodeSession(encodeSession(s)); !ok || got != s {
			t.Errorf("round trip of %+v = %+v, %v", s, got, ok)
		}
	}

	good := encodeSession(session{class: humanVisits, exit: "/b", host: "h", last: 1})
	withClass := func(cl class) []byte { return append([]byte{sessionVersion, byte(cl)}, good[2:]...) }

	for name, b := range map[string][]byte{
		"empty":           {},
		"no class":        {sessionVersion},
		"version 0":       append([]byte{0}, good[1:]...),
		"error class":     withClass(newClass(false, groupError)),
		"unknown class":   withClass(numClasses),
		"cut varint":      {sessionVersion, 0, 0x80},
		"varint overflow": append([]byte{sessionVersion, 0}, bytes.Repeat([]byte{0xff}, 11)...),
		"missing strings": good[:len(good)-3],
		"string too long": append(append([]byte(nil), good[:len(good)-3]...), 9, '/', 'b'),
		"trailing bytes":  append(append([]byte(nil), good...), 0),
	} {
		if _, ok := decodeSession(b); ok {
			t.Errorf("%s %x: decoded", name, b)
		}
	}
}
