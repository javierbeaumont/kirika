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

// Package uaclass classifies a User-Agent string as a bot, desktop or mobile client by lowercase substring markers.
package uaclass

import "strings"

// Client kinds returned by Classify.
const (
	Bot     = "bot"
	Desktop = "desktop"
	Mobile  = "mobile"
)

// Substrings common to crawlers and automated clients.
var botMarkers = []string{
	"bingpreview", "bot", "crawl", "curl", "facebookexternalhit", "feedfetcher", "go-http-client", "httpclient",
	"libwww", "mediapartners", "monitor", "python-requests", "scrapy", "slurp", "spider", "wget",
}

// Substrings common to handheld devices.
var mobileMarkers = []string{
	"android", "bb10", "blackberry", "ipad", "iphone", "ipod", "kaios", "mobi", "opera mini", "windows phone",
}

// Classify returns the client kind of a User-Agent string, ignoring case. A blank string is Bot, since every browser
// sends a User-Agent. Bot markers win over mobile ones, as crawlers can announce a phone; a string with neither is
// Desktop.
func Classify(ua string) string {
	s := strings.ToLower(ua)

	switch {
	case strings.TrimSpace(s) == "" || containsAny(s, botMarkers):
		return Bot
	case containsAny(s, mobileMarkers):
		return Mobile
	default:
		return Desktop
	}
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}

	return false
}
