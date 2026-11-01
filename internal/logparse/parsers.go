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

import "fmt"

// Parser decodes a single raw access-log line into an Event.
type Parser func(line []byte) (Event, error)

// ByName returns the parser registered under a log-format name.
func ByName(name string) (Parser, error) {
	switch name {
	case "caddy-json":
		return ParseCaddyJSON, nil
	default:
		return nil, fmt.Errorf("logparse: unknown format %q", name)
	}
}
