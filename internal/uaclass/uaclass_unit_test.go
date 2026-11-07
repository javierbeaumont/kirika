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

package uaclass

import (
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	for _, tc := range []struct{ ua, want string }{
		{"", Bot},
		{" \t", Bot},
		{"CURL/8.7.1", Bot},
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", Bot},
		{"Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 " +
			"Safari/604.1", Mobile},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) " +
			"Version/17.0 Mobile/15E148 Safari/604.1", Mobile},
		{"Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) " +
			"Chrome/120.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", Bot},
		{"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile " +
			"Safari/537.36", Mobile},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 " +
			"Safari/605.1.15", Desktop},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 " +
			"Safari/537.36", Desktop},
	} {
		if got := Classify(tc.ua); got != tc.want {
			t.Errorf("Classify(%q) = %q, want %q", tc.ua, got, tc.want)
		}
	}
}

// Every marker, in any case, decides its kind on its own, and a bot marker wins over every mobile one.
func TestClassifyMarkers(t *testing.T) {
	for kind, markers := range map[string][]string{Bot: botMarkers, Mobile: mobileMarkers} {
		for _, m := range markers {
			if got := Classify("x " + strings.ToUpper(m) + " x"); got != kind {
				t.Errorf("marker %q: Classify = %q, want %q", m, got, kind)
			}
		}
	}

	for _, bot := range botMarkers {
		for _, mobile := range mobileMarkers {
			if got := Classify(mobile + " " + bot); got != Bot {
				t.Errorf("markers %q and %q: Classify = %q, want %q", mobile, bot, got, Bot)
			}
		}
	}
}

// Each list stays lowercase, sorted and free of duplicates.
func TestMarkerLists(t *testing.T) {
	for name, markers := range map[string][]string{"botMarkers": botMarkers, "mobileMarkers": mobileMarkers} {
		for i, m := range markers {
			if m == "" || m != strings.ToLower(m) {
				t.Errorf("%s[%d] = %q, want a non-empty lowercase marker", name, i, m)
			}

			if i > 0 && m <= markers[i-1] {
				t.Errorf("%s: %q after %q, want sorted and unique", name, m, markers[i-1])
			}
		}
	}
}
