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
	"strings"
	"testing"
)

func TestExtension(t *testing.T) {
	for path, want := range map[string]string{
		"":            "",
		"/":           "",
		"/a":          "",
		"/a.":         "",
		"/a.b":        "b",
		"/A.PNG":      "png",
		"/a.abcdefg":  "abcdefg",
		"/a.b_9":      "b_9",
		"/a.b-c":      "",
		"/a.\u00f1":   "\u00f1",
		"/A.\u00d1":   "\u00f1",
		"/a.n\u0303":  "n\u0303",
		"/a.\u2160":   "\u2170",
		"/a.\u24b6":   "\u24d0",
		"/a.b\u203fc": "b\u203fc",
		"/a.b\u200dc": "b\u200dc",
		"/a.\u20ac":   "",
		"/a.\xff":     "",
		"/a.%C3%B1":   "",
		"/v1.2/docs":  "",
		"/x.tar.gz":   "gz",
		"/.htaccess":  "htaccess",
		"/dir.d/file": "",
		"png":         "",
	} {
		if got := extension(path); got != want {
			t.Errorf("extension(%q) = %q, want %q", path, got, want)
		}
	}
}

// An extension has no length limit.
func TestExtensionLength(t *testing.T) {
	long := strings.Repeat("a", 100)
	if got := extension("/a." + long); got != long {
		t.Errorf("extension of a %d-letter extension = %q, want it whole", len(long), got)
	}
}

// Checks the default rule: no extension, or an unknown one, is a page; a file type is not.
func TestIsPage(t *testing.T) {
	notPage := notPageSet(nil, nil)

	for path, want := range map[string]bool{
		"":                 true,
		"/":                true,
		"/blog/post-1":     true,
		"/v1.2":            true,
		"/index.html":      true,
		"/INDEX.HTML":      true,
		"/search.php":      true,
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
		"/pkgs/kirika.rpm": false,
		"/kirika.AppImage": false,
		"/kirika.flatpak":  false,
		"/kirika.snap":     false,
		"/kirika.tar.zst":  false,
		"/app.flatpakref":  false,
		"/setup.exe":       false,
		"/photo.avif":      false,
		"/live.m3u8":       false,
		"/live0.ts":        false,
		"/app.mjs":         false,
		"/app.wasm":        false,
		"/app.js.map":      false,
		"/font.ttf":        false,
		"/font.otf":        false,
		"/a.webmanifest":   false,
		"/feed.atom":       false,
		"/data.json":       false,
		"/lib.dll":         false,
		"/kirika.sig":      false,
		"/kirika.sha256":   false,
		"/lib.jar.sha1":    false,
		"/kirika.torrent":  false,
		"/.env":            false,
		"/.htaccess":       false,
		"/dump.sql":        false,
		"/config.yml":      false,
		"/pages.html/a.js": false,
	} {
		if got := isPage(path, notPage); got != want {
			t.Errorf("isPage(%q) = %v, want %v", path, got, want)
		}
	}
}

// NotPages adds to the file types and Pages takes from both, in any letter case. Neither reaches another set.
func TestNotPageSet(t *testing.T) {
	notPage := notPageSet([]string{"ACTION", "Txt", "\u00d1"}, []string{"JSON", "txt"})

	for path, want := range map[string]bool{
		"/save.action": false, "/data.json": true, "/notes.txt": true, "/app.css": false, "/blog/post": true,
		"/a.\u00f1": false,
	} {
		if got := isPage(path, notPage); got != want {
			t.Errorf("isPage(%q) = %v, want %v", path, got, want)
		}
	}

	if notPage = notPageSet(nil, nil); notPage["action"] || !notPage["json"] {
		t.Errorf("one set's lists reached the file types: action %v, json %v", notPage["action"], notPage["json"])
	}
}

// An empty NotPages entry leaves a path with no extension a page.
func TestIsPageEmptyEntry(t *testing.T) {
	if !isPage("/", setOf("")) {
		t.Error(`isPage("/") with an empty entry listed = false, want true`)
	}
}

// A path folds only when it ends in "/" and an index page, in the same case.
func TestFold(t *testing.T) {
	suffixes := []string{"/index.html", "/index.php"}

	for path, want := range map[string]string{
		"/index.html":     "/",
		"/blog/index.php": "/blog/",
		"/blog/":          "/blog/",
		"/INDEX.HTML":     "/INDEX.HTML",
		"/myindex.html":   "/myindex.html",
		"/index.html/":    "/index.html/",
		"index.html":      "index.html",
	} {
		if got := fold(path, suffixes); got != want {
			t.Errorf("fold(%q) = %q, want %q", path, got, want)
		}
	}
}

// A string is cut at the first of chars, and kept whole without any.
func TestCutAt(t *testing.T) {
	for _, tc := range []struct{ value, chars, want string }{
		{"/a?q", "?", "/a"},
		{"/a;s?q", "?;", "/a"},
		{"/a?q;s", "?;", "/a"},
		{"/a;s", "?", "/a;s"},
		{"/a", "?;", "/a"},
		{"?q", "?", ""},
		{"/a#f?q", "#?", "/a"},
		{"/a?q#f", "#?", "/a"},
	} {
		if got := cutAt(tc.value, tc.chars); got != tc.want {
			t.Errorf("cutAt(%q, %q) = %q, want %q", tc.value, tc.chars, got, tc.want)
		}
	}
}

func TestDefaultOptions(t *testing.T) {
	o := DefaultOptions()
	o.IndexPages[0] = "x"
	o.ValidCodes[0] = 0

	if defaults := DefaultOptions(); defaults.IndexPages[0] == "x" || defaults.ValidCodes[0] == 0 {
		t.Errorf("a change to the returned options reached the defaults: %+v", defaults)
	}
}
