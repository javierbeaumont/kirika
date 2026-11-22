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

package ingest

import (
	"errors"
	"io/fs"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/javierbeaumont/kirika/internal/logparse"
)

// The names Caddy gives a rotated access.log by default, with a time, and logrotate with dateext, with a date.
var (
	caddyName = "access-" + base.Format("2006-01-02T15-04-05.000")
	datedName = "access.log-" + base.Format("20060102")
)

// The default globs match logrotate's numbered and dated names and Caddy's, compressed or not, and no other log beside
// the one rotated; a name with pattern characters matches only itself.
func TestDefaultRotated(t *testing.T) {
	for _, tc := range []struct {
		base, name string
		want       bool
	}{
		{"access.log", "access.log.1", true},
		{"access.log", "access.log.2.gz", true},
		{"access.log", datedName, true},
		{"access.log", datedName + ".gz", true},
		{"access.log", caddyName + "-size.log", true},
		{"access.log", caddyName + ".log.gz", true},
		{"access.log", "access.log", false},
		{"access.log", "access-api.log", false},
		{"access.log", "access-8080.log", false},
		{"access.log", "access-2.log", false},
		{"access.log", "access.log-8080", false},
		{"access.log", "access.log.old", false},
		{"access.log", "other.log.1", false},
		{"access", "access.1", true},
		{"access", caddyName + "-size", true},
		{"a[1].log", "a[1].log.1", true},
		{"a[1].log", "a1.log.1", false},
	} {
		matched := slices.ContainsFunc(defaultRotated(tc.base), func(pattern string) bool {
			ok, err := filepath.Match(pattern, tc.name)

			return ok && err == nil
		})
		if matched != tc.want {
			t.Errorf("defaultRotated(%q) matches %q: %v, want %v", tc.base, tc.name, matched, tc.want)
		}
	}
}

// An escaped name matches only itself: *, ? and [ each in a class, and a backslash escaped.
func TestEscapeGlob(t *testing.T) {
	name := `a*b?c[d]e\f`
	if got := escapeGlob(name); got != `a[*]b[?]c[[]d]e\\f` {
		t.Errorf("escapeGlob(%q) = %q", name, got)
	}

	for _, other := range []string{name, "aXbYc[d]e\\f", "axbycde\\f"} {
		if ok, err := filepath.Match(escapeGlob(name), other); ok != (other == name) || err != nil {
			t.Errorf("escapeGlob(%q) matches %q: %v, %v", name, other, ok, err)
		}
	}
}

// Two of logrotate's numbered names of one log order by their number, the lower first; no other two do: a time's
// milliseconds are no number of logrotate's.
func TestByNumber(t *testing.T) {
	later := "access-" + base.Add(500*time.Millisecond).Format("2006-01-02T15-04-05.000")

	for _, tc := range []struct {
		a, b  string
		order int
		ok    bool
	}{
		{"access.log.1", "access.log.2", -1, true},
		{"access.log.10", "access.log.9", 1, true},
		{"access.log.2.gz", "access.log.10", -1, true},
		{"access.log.2.gz", "access.log.1", 1, true},
		{"access.log.1", "other.log.2", 0, false},
		{datedName, "access.log-" + base.AddDate(0, 0, 1).Format("20060102"), 0, false},
		{caddyName, later, 0, false},
	} {
		if order, ok := byNumber(tc.a, tc.b); order != tc.order || ok != tc.ok {
			t.Errorf("byNumber(%q, %q) = %d, %v; want %d, %v", tc.a, tc.b, order, ok, tc.order, tc.ok)
		}
	}
}

// A file's information with only its modification time.
type timedInfo struct {
	fs.FileInfo

	modified time.Time
}

func (i timedInfo) ModTime() time.Time { return i.modified }

// Rotated files order newer first: logrotate's numbered ones by their number whatever their time, any other by time,
// then by name, the later first.
func TestNewerFirst(t *testing.T) {
	rotated := func(name string, hours int) rotatedFile {
		return rotatedFile{info: timedInfo{modified: base.Add(time.Duration(hours) * time.Hour)}, name: name}
	}

	for _, tc := range []struct {
		a, b rotatedFile
		want int
	}{
		{rotated("access.log.1", 1), rotated("access.log.2.gz", 2), -1},
		{rotated(datedName, 2), rotated(caddyName+".log", 1), -1},
		{rotated(datedName, 1), rotated("access.log-"+base.AddDate(0, 0, 1).Format("20060102"), 1), 1},
	} {
		if got := newerFirst(tc.a, tc.b); got != tc.want {
			t.Errorf("newerFirst(%q, %q) = %d, want %d", tc.a.name, tc.b.name, got, tc.want)
		}
	}
}

// Of the compressed formats other than gzip, bzip2 wants its block size and block magic after "BZh", which a line of
// text may start with; xz and zstd their own magic.
func TestOtherCompression(t *testing.T) {
	for head, want := range map[string]bool{
		"BZh91AY&SY":       true,
		"BZh9":             false,
		"BZh9xxxxxx":       false,
		"BZhX1AY&SY":       false,
		"BZhang-pc":        false,
		"\xfd7zXZ\x00":     true,
		"\x28\xb5\x2f\xfd": true,
		"\x1f\x8b":         false,
		"192.0.2.1":        false,
	} {
		if got := otherCompression([]byte(head)); got != want {
			t.Errorf("otherCompression(%q) = %v, want %v", head, got, want)
		}
	}
}

// New takes a relative glob of rotated files from the log's escaped directory, and an absolute one as it is; nil is the
// default globs, and New refuses a malformed glob.
func TestNewRotated(t *testing.T) {
	path := filepath.Join(string(filepath.Separator)+"logs", "[a]", "access.log")
	dir := "/logs/[[]a]/"

	for _, tc := range []struct {
		rotated, want []string
	}{
		{nil, []string{
			dir + "access.log.[0-9]*", dir + "access.log-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]*",
			dir + "access-[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T*.log*",
		}},
		{[]string{}, nil},
		{[]string{"old/*.gz", "/archive/access.log.*"}, []string{dir + "old/*.gz", "/archive/access.log.*"}},
	} {
		options := DefaultOptions()
		options.Rotated = tc.rotated

		logReader, err := New(nil, path, logparse.ParseNCSA, options)
		if err != nil {
			t.Fatalf("New with the globs %q: %v", tc.rotated, err)
		}

		if !slices.Equal(logReader.rotated, tc.want) {
			t.Errorf("New with the globs %q: %q; want %q", tc.rotated, logReader.rotated, tc.want)
		}
	}

	options := DefaultOptions()
	options.Rotated = []string{"access.log.["}

	if _, err := New(nil, path, logparse.ParseNCSA, options); !errors.Is(err, filepath.ErrBadPattern) {
		t.Errorf("New with a malformed glob: %v, want filepath.ErrBadPattern", err)
	}
}
