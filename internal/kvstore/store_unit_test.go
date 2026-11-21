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
	"os"
	"testing"
)

// TZ names the zone when set, an empty one meaning UTC, or a path in it is or links to the zone. Without TZ, that path
// is /etc/localtime; when it names no zone, /etc/timezone or /var/db/zoneinfo does. Else it is UTC. A zoneinfo
// directory itself names no zone.
func TestSystemZone(t *testing.T) {
	const (
		local  = "/etc/localtime"
		named  = "/etc/timezone"
		bsd    = "/var/db/zoneinfo"
		sydney = "/usr/share/zoneinfo/Australia/Sydney"
	)

	type paths = map[string]string

	for _, tc := range []struct {
		tz           string
		tzSet        bool
		links, files paths
		want         string
	}{
		{tz: "America/Chicago", tzSet: true, links: paths{local: sydney}, want: "America/Chicago"},
		{tz: ":Africa/Cairo", tzSet: true, want: "Africa/Cairo"},
		{tz: "/usr/share/zoneinfo/Europe/Lisbon", tzSet: true, want: "Europe/Lisbon"},
		{tz: "", tzSet: true, links: paths{local: sydney}, want: "UTC"},
		{tz: ":/etc/localtime", tzSet: true, links: paths{local: sydney}, want: "Australia/Sydney"},
		{tz: ":/etc/localtime", tzSet: true, files: paths{named: "Asia/Seoul"}, want: "Asia/Seoul"},
		{tz: "/opt/zone", tzSet: true, links: paths{"/opt/zone": sydney}, want: "Australia/Sydney"},
		{tz: "/opt/zone", tzSet: true, files: paths{named: "Asia/Seoul"}, want: "UTC"},
		{tz: "/usr/share/zoneinfo/", tzSet: true, want: "UTC"},
		{links: paths{local: sydney}, want: "Australia/Sydney"},
		{links: paths{local: "/var/db/timezone/zoneinfo/America/Denver"}, want: "America/Denver"},
		{links: paths{local: "/etc/zone"}, want: "UTC"},
		{links: paths{local: "/etc/zone"}, files: paths{named: "America/Lima"}, want: "America/Lima"},
		{links: paths{local: "/usr/share/zoneinfo/"}, files: paths{named: "America/Lima"}, want: "America/Lima"},
		{files: paths{named: " Africa/Lagos\n", bsd: "Europe/Oslo"}, want: "Africa/Lagos"},
		{files: paths{named: "\n", bsd: "Europe/Oslo\n"}, want: "Europe/Oslo"},
		{want: "UTC"},
	} {
		getenv := func(key string) (string, bool) {
			if key != "TZ" {
				t.Errorf("getenv(%q), want TZ", key)
			}

			return tc.tz, tc.tzSet
		}
		lookup := func(m paths) func(string) (string, error) {
			return func(path string) (string, error) {
				if v, ok := m[path]; ok {
					return v, nil
				}

				return "", os.ErrNotExist
			}
		}

		if got := systemZone(getenv, lookup(tc.links), lookup(tc.files)); got != tc.want {
			t.Errorf("TZ %q (set %v), links %v, files %q: %q, want %q",
				tc.tz, tc.tzSet, tc.links, tc.files, got, tc.want)
		}
	}
}

// A zone of the tz database's posix/ or right/ copies loses that prefix; any other, and either prefix alone, is kept.
func TestPlainZone(t *testing.T) {
	for zone, want := range map[string]string{
		"posix/Europe/Madrid": "Europe/Madrid",
		"right/Europe/Madrid": "Europe/Madrid",
		"right/UTC":           "UTC",
		"Europe/Madrid":       "Europe/Madrid",
		"posixrules":          "posixrules",
		"Etc/posix/UTC":       "Etc/posix/UTC",
		"posix/":              "posix/",
		"right/":              "right/",
		"":                    "",
	} {
		if got := plainZone(zone); got != want {
			t.Errorf("plainZone(%q) = %q, want %q", zone, got, want)
		}
	}
}
