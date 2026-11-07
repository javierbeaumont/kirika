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

package logparse

import "testing"

func TestClientAddr(t *testing.T) {
	for in, want := range map[string]string{
		"":                 "",
		"192.0.2.1":        "192.0.2.1",
		"192.0.2.1:80":     "192.0.2.1",
		"2001:db8::1":      "2001:db8::1",
		"[2001:db8::1]":    "2001:db8::1",
		"[2001:db8::1]:80": "2001:db8::1",
		"[2001:db8::1":     "[2001:db8::1",
		"2001:db8::1]":     "2001:db8::1]",
		"client.example:1": "client.example",
	} {
		if got := clientAddr(in); got != want {
			t.Errorf("clientAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

// Checks the decoded characters, those just outside their ranges, and escapes cut short or not hex.
func TestUnreserved(t *testing.T) {
	for in, want := range map[string]string{
		"/a/b":                      "/a/b",
		"%7E/%7e":                   "~/~",
		"/%41%5A%61%7A%30%39":       "/AZaz09",
		"/%2D%2E%5F":                "/-._",
		"/%40%5B%60%7B%2F%3A%20%E2": "/%40%5B%60%7B%2F%3A%20%E2",
		"/%":                        "/%",
		"/%4":                       "/%4",
		"/%4G%G4%Z1":                "/%4G%G4%Z1",
	} {
		if got := unreserved(in); got != want {
			t.Errorf("unreserved(%q) = %q, want %q", in, got, want)
		}
	}
}
