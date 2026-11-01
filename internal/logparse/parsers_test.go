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

import "testing"

// TestByName checks that each name returns its own parser, by parsing a line only that format accepts.
func TestByName(t *testing.T) {
	for name, line := range map[string][]byte{
		"caddy-json": caddyRequest(`"host":"example.com"`),
	} {
		p, err := ByName(name)
		if err != nil {
			t.Fatalf("ByName(%q): %v", name, err)
		}

		if _, err := p(line); err != nil {
			t.Errorf("ByName(%q) parser: %v", name, err)
		}
	}

	for _, name := range []string{"", "CADDY-JSON", "unknown"} {
		if _, err := ByName(name); err == nil {
			t.Errorf("ByName(%q): want error, got nil", name)
		}
	}
}
