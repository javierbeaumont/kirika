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

import "testing"

func TestExtension(t *testing.T) {
	for path, want := range map[string]string{
		"":            "",
		"/":           "",
		"/a":          "",
		"/a.":         "",
		"/a.b":        "b",
		"/A.PNG":      "png",
		"/a.abcdef":   "abcdef",
		"/a.abcdefg":  "",
		"/a.b_9":      "b_9",
		"/a.b-c":      "",
		"/a.ñ":        "",
		"/v1.2/docs":  "",
		"/x.tar.gz":   "gz",
		"/.htaccess":  "",
		"/dir.d/file": "",
	} {
		if got := extension(path); got != want {
			t.Errorf("extension(%q) = %q, want %q", path, got, want)
		}
	}
}

// Checks the default rule: no extension, or an unknown one, is a page; an extension in the list or of an image or
// download type is not.
func TestIsPage(t *testing.T) {
	notPage := setOf(DefaultOptions().NotPages...)

	for path, want := range map[string]bool{
		"":                 true,
		"/":                true,
		"/blog/post-1":     true,
		"/v1.2":            true,
		"/index.html":      true,
		"/INDEX.HTML":      true,
		"/search.php":      true,
		"/data.json":       true,
		"/feed.atom":       true,
		"/.htaccess":       true,
		"/app.css":         false,
		"/APP.JS":          false,
		"/feed.xml":        false,
		"/font.woff2":      false,
		"/logo.png":        false,
		"/photo.heic":      false,
		"/doc.pdf":         false,
		"/notes.txt":       false,
		"/video.mp4":       false,
		"/x.tar.gz":        false,
		"/pages.html/a.js": false,
	} {
		if got := isPage(path, notPage); got != want {
			t.Errorf("isPage(%q) = %v, want %v", path, got, want)
		}
	}
}

// The list replaces the default one, in any case, while image and download types stay files.
func TestIsPageList(t *testing.T) {
	notPage := setOf("JSON")

	for path, want := range map[string]bool{"/data.json": false, "/app.css": true, "/doc.pdf": false} {
		if got := isPage(path, notPage); got != want {
			t.Errorf("isPage(%q) with json listed = %v, want %v", path, got, want)
		}
	}
}

func TestDefaultOptions(t *testing.T) {
	o := DefaultOptions()
	o.NotPages[0] = "html"
	o.ValidCodes[0] = 0

	if d := DefaultOptions(); d.NotPages[0] == "html" || d.ValidCodes[0] == 0 {
		t.Errorf("a change to the returned options reached the defaults: %+v", d)
	}
}
