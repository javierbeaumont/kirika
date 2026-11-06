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

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	berrors "go.etcd.io/bbolt/errors"
)

// Writes a raw meta value under key into the store at path.
func setMeta(t *testing.T, path string, key, v []byte) {
	t.Helper()

	b, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatalf("bolt open: %v", err)
	}

	err = b.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bktMeta).Put(key, v)
	})
	if err != nil {
		t.Fatalf("set %s: %v", key, err)
	}

	if err := b.Close(); err != nil {
		t.Fatalf("bolt close: %v", err)
	}
}

// Closes db, failing the test on error.
func closeStore(t *testing.T, db *DB) {
	t.Helper()

	if err := db.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

// Returns the path of a store created and closed in a fresh directory.
func storePath(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "kirika.db")

	db, err := Open(path, time.Second, "UTC")
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	closeStore(t, db)

	return path
}

func TestOpen(t *testing.T) {
	path := storePath(t)

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}

	db, err := Open(path, time.Second, "UTC")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	defer closeStore(t, db)

	err = db.b.View(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bktAgg, bktSess, bktUniq} {
			if tx.Bucket(name) == nil {
				t.Errorf("no %s bucket", name)
			}
		}

		if v := tx.Bucket(bktMeta).Get(metaSchema); !bytes.Equal(v, []byte{schemaVersion}) {
			t.Errorf("schema = %x, want %x", v, schemaVersion)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("view: %v", err)
	}
}

func TestOpenErrors(t *testing.T) {
	dir := t.TempDir()

	notStore := filepath.Join(dir, "access.log")
	if err := os.WriteFile(notStore, []byte("not a bbolt file\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	for _, path := range []string{dir, filepath.Join(dir, "missing", "kirika.db"), notStore} {
		if _, err := Open(path, time.Second, "UTC"); err == nil || errors.Is(err, berrors.ErrTimeout) {
			t.Errorf("Open(%s): err = %v, want an error other than the lock timeout", path, err)
		}
	}
}

func TestOpenLocked(t *testing.T) {
	path := storePath(t)

	db, err := Open(path, time.Second, "UTC")
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	if _, err := Open(path, 50*time.Millisecond, "UTC"); !errors.Is(err, berrors.ErrTimeout) {
		t.Errorf("second open: err = %v, want the lock timeout", err)
	}

	closeStore(t, db)

	db, err = Open(path, time.Second, "UTC")
	if err != nil {
		t.Fatalf("open after close: %v", err)
	}

	closeStore(t, db)
}

// Each bad stored version is refused with its error, and a refused store releases its lock.
func TestOpenSchema(t *testing.T) {
	for _, tc := range []struct {
		v    []byte
		want error
	}{
		{[]byte{}, errSchemaCorrupt},
		{[]byte{0}, errSchemaCorrupt},
		{[]byte{schemaVersion, 0}, errSchemaCorrupt},
		{[]byte{schemaVersion + 1}, errSchemaNewer},
	} {
		path := storePath(t)
		setMeta(t, path, metaSchema, tc.v)

		for _, timeout := range []time.Duration{time.Second, 50 * time.Millisecond} {
			db, err := Open(path, timeout, "UTC")
			if err == nil {
				closeStore(t, db)
			}

			if !errors.Is(err, tc.want) {
				t.Errorf("schema %q, timeout %v: err = %v, want %v", tc.v, timeout, err, tc.want)
			}
		}
	}
}

// A store's salt is generated once, kept across opens and its own.
func TestSalt(t *testing.T) {
	salts := make([][]byte, 0, 4)

	for _, path := range []string{storePath(t), storePath(t)} {
		for range 2 {
			db, err := Open(path, time.Second, "UTC")
			if err != nil {
				t.Fatalf("open: %v", err)
			}

			salts = append(salts, db.salt)
			closeStore(t, db)
		}
	}

	if len(salts[0]) != saltLen {
		t.Errorf("salt of %d bytes, want %d", len(salts[0]), saltLen)
	}

	if !bytes.Equal(salts[0], salts[1]) {
		t.Error("the salt changed on reopening")
	}

	if bytes.Equal(salts[0], salts[2]) {
		t.Error("two stores have the same salt")
	}
}

// A stored salt of another size is refused, and the refused store releases its lock.
func TestSaltCorrupt(t *testing.T) {
	for _, salt := range [][]byte{{}, make([]byte, saltLen-1), make([]byte, saltLen+1)} {
		path := storePath(t)
		setMeta(t, path, metaSalt, salt)

		for _, timeout := range []time.Duration{time.Second, 50 * time.Millisecond} {
			db, err := Open(path, timeout, "UTC")
			if err == nil {
				closeStore(t, db)
			}

			if !errors.Is(err, errSaltCorrupt) {
				t.Errorf("salt of %d bytes, timeout %v: err = %v, want errSaltCorrupt", len(salt), timeout, err)
			}
		}
	}
}

// Opens the store at path with zone and returns the name of the zone it counts in.
func openZone(t *testing.T, path, zone string) (string, error) {
	t.Helper()

	db, err := Open(path, time.Second, zone)
	if err != nil {
		return "", err
	}

	defer closeStore(t, db)

	return db.Zone(), nil
}

// A new store keeps the configured zone, else the system's. Reopened, it keeps that zone and refuses another. A zone
// the system does not know is refused, whether configured or stored, and never kept.
func TestOpenZone(t *testing.T) {
	t.Setenv("TZ", "America/Sao_Paulo")

	path := filepath.Join(t.TempDir(), "kirika.db")
	if _, err := openZone(t, path, "Nowhere/Nothing"); err == nil {
		t.Error("unknown configured zone: no error")
	}

	if got, err := openZone(t, path, ""); got != "America/Sao_Paulo" {
		t.Errorf("new store, no zone: %q, %v; want the system's America/Sao_Paulo", got, err)
	}

	t.Setenv("TZ", "Africa/Nairobi")

	for _, zone := range []string{"", "America/Sao_Paulo"} {
		if got, err := openZone(t, path, zone); got != "America/Sao_Paulo" {
			t.Errorf("reopened with %q: %q, %v; want the stored America/Sao_Paulo", zone, got, err)
		}
	}

	if _, err := openZone(t, path, "Africa/Nairobi"); !errors.Is(err, errZone) {
		t.Errorf("reopened with another zone: err = %v, want errZone", err)
	}

	if got, err := openZone(t, filepath.Join(t.TempDir(), "kirika.db"), "UTC"); got != "UTC" {
		t.Errorf("new store in UTC: %q, %v; want UTC over the system's", got, err)
	}

	setMeta(t, path, metaZone, []byte("Nowhere/Nothing"))

	if _, err := openZone(t, path, ""); err == nil {
		t.Error("unknown stored zone: no error")
	}
}

// A new store takes the system's zone from the real environment and file system: TZ holds the path of a link into a
// zoneinfo directory.
func TestOpenSystemZone(t *testing.T) {
	link := filepath.Join(t.TempDir(), "localtime")
	if err := os.Symlink("/usr/share/zoneinfo/Pacific/Auckland", link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	t.Setenv("TZ", link)

	if got, err := openZone(t, filepath.Join(t.TempDir(), "kirika.db"), ""); got != "Pacific/Auckland" {
		t.Errorf("TZ links to Pacific/Auckland: %q, %v; want Pacific/Auckland", got, err)
	}
}

// TZ names the zone when set, an empty one meaning UTC, or a path in it links to the zone. Without TZ, /etc/localtime
// links to it, or /etc/timezone or /var/db/zoneinfo names a copy there. Else it is UTC.
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
		{links: paths{local: sydney}, want: "Australia/Sydney"},
		{links: paths{local: "/var/db/timezone/zoneinfo/America/Denver"}, want: "America/Denver"},
		{links: paths{local: "/etc/zone"}, want: "UTC"},
		{links: paths{local: "/etc/zone"}, files: paths{named: "America/Lima"}, want: "America/Lima"},
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

func TestReadText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "timezone")
	if err := os.WriteFile(path, []byte("America/Halifax\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if got, err := readText(path); got != "America/Halifax\n" || err != nil {
		t.Errorf("readText = %q, %v; want the file's text", got, err)
	}

	if _, err := readText(path + ".missing"); err == nil {
		t.Error("readText of a missing file: no error")
	}
}
