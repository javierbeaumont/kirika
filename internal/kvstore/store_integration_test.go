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

//go:build integration

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

// Runs update in one transaction on the bbolt file at path, created if missing, opened with options.
func updateFile(t *testing.T, path string, options *bolt.Options, update func(*bolt.Tx) error) {
	t.Helper()

	file, err := bolt.Open(path, 0o600, options)
	if err != nil {
		t.Fatalf("bolt open: %v", err)
	}

	if err := file.Update(update); err != nil {
		t.Fatalf("update %s: %v", filepath.Base(path), err)
	}

	if err := file.Close(); err != nil {
		t.Fatalf("bolt close: %v", err)
	}
}

// Fails the test unless the file at path opens to write, as when no process holds its lock.
func checkUnlocked(t *testing.T, path string) {
	t.Helper()

	file, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 50 * time.Millisecond})
	if err != nil {
		t.Errorf("open %s to write: %v", filepath.Base(path), err)

		return
	}

	if err := file.Close(); err != nil {
		t.Errorf("bolt close: %v", err)
	}
}

// Writes a raw meta value under key into the store at path.
func setMeta(t *testing.T, path string, key, v []byte) {
	t.Helper()

	updateFile(t, path, nil, func(tx *bolt.Tx) error {
		return tx.Bucket(bktMeta).Put(key, v)
	})
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
		for _, name := range [][]byte{bktAgg, bktKeys, bktSess, bktState, bktUniq} {
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

// Open waits no longer than its timeout for a file held to write or to read.
func TestOpenLocked(t *testing.T) {
	path := storePath(t)

	db, err := Open(path, time.Second, "UTC")
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	if _, err := Open(path, 50*time.Millisecond, "UTC"); !errors.Is(err, berrors.ErrTimeout) {
		t.Errorf("open of a store held to write: err = %v, want the lock timeout", err)
	}

	closeStore(t, db)

	reader, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true})
	if err != nil {
		t.Fatalf("bolt open to read: %v", err)
	}

	if _, err := Open(path, 50*time.Millisecond, "UTC"); !errors.Is(err, berrors.ErrTimeout) {
		t.Errorf("open of a store held to read: err = %v, want the lock timeout", err)
	}

	if err := reader.Close(); err != nil {
		t.Fatalf("bolt close: %v", err)
	}

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

		db, err := Open(path, time.Second, "UTC")
		if err == nil {
			closeStore(t, db)
		}

		if !errors.Is(err, tc.want) {
			t.Errorf("schema %q: err = %v, want %v", tc.v, err, tc.want)
		}

		checkUnlocked(t, path)
	}
}

// A file with buckets but no schema version, such as another program's, is refused and left as it was, even one saved
// without its free-page list, which bbolt writes to when it opens it to write. A refused file releases its lock.
func TestOpenNotStore(t *testing.T) {
	dir := t.TempDir()
	foreign := filepath.Join(dir, "other.db")
	noFreelist := filepath.Join(dir, "no-freelist.db")

	for path, options := range map[string]*bolt.Options{foreign: nil, noFreelist: {NoFreelistSync: true}} {
		updateFile(t, path, options, func(tx *bolt.Tx) error {
			bucket, err := tx.CreateBucket([]byte("other"))
			if err != nil {
				return err
			}

			return bucket.Put([]byte("key"), []byte("value"))
		})
	}

	noSchema := storePath(t)
	updateFile(t, noSchema, nil, func(tx *bolt.Tx) error {
		return tx.Bucket(bktMeta).Delete(metaSchema)
	})

	for _, path := range []string{foreign, noFreelist, noSchema} {
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read: %v", err)
		}

		db, err := Open(path, time.Second, "UTC")
		if err == nil {
			closeStore(t, db)
		}

		if !errors.Is(err, errNotStore) {
			t.Errorf("Open(%s): err = %v, want %v", filepath.Base(path), err, errNotStore)
		}

		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read: %v", err)
		}

		if !bytes.Equal(after, before) {
			t.Errorf("Open(%s) changed the file", filepath.Base(path))
		}

		checkUnlocked(t, path)
	}
}

// init refuses what probe refuses, as the file may change between the two opens.
func TestInitRefuses(t *testing.T) {
	foreign := filepath.Join(t.TempDir(), "other.db")
	updateFile(t, foreign, nil, func(tx *bolt.Tx) error {
		_, err := tx.CreateBucket([]byte("other"))

		return err
	})

	newer := storePath(t)
	setMeta(t, newer, metaSchema, []byte{schemaVersion + 1})

	for path, want := range map[string]error{foreign: errNotStore, newer: errSchemaNewer} {
		file, err := bolt.Open(path, 0o600, nil)
		if err != nil {
			t.Fatalf("bolt open: %v", err)
		}

		if err := (&DB{b: file}).init("UTC"); !errors.Is(err, want) {
			t.Errorf("init(%s): err = %v, want %v", filepath.Base(path), err, want)
		}

		if err := file.Close(); err != nil {
			t.Fatalf("bolt close: %v", err)
		}
	}
}

// A file with no bucket, even an empty one, becomes a new store.
func TestOpenEmptyFile(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.db")
	noBucket := filepath.Join(dir, "no-bucket.db")

	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	updateFile(t, noBucket, nil, func(*bolt.Tx) error { return nil })

	for _, path := range []string{empty, noBucket} {
		db, err := Open(path, time.Second, "UTC")
		if err != nil {
			t.Errorf("Open(%s): %v", filepath.Base(path), err)

			continue
		}

		err = db.b.View(func(tx *bolt.Tx) error {
			if version := tx.Bucket(bktMeta).Get(metaSchema); !bytes.Equal(version, []byte{schemaVersion}) {
				t.Errorf("Open(%s): schema = %x, want %x", filepath.Base(path), version, schemaVersion)
			}

			return nil
		})
		if err != nil {
			t.Errorf("view: %v", err)
		}

		closeStore(t, db)
	}
}

// Every read of a closed store is an error.
func TestClosedStore(t *testing.T) {
	db := openStore(t)
	closeStore(t, db)

	for name, read := range map[string]func() error{
		"Totals": func() error {
			_, err := db.Totals("h", "2000", Filter{})

			return err
		},
		"Series": func() error {
			_, err := db.Series("h", tagDay, "2000", Filter{})

			return err
		},
		"Dim": func() error {
			_, err := db.Dim("h", tagURL, "2000", Filter{})

			return err
		},
		"Hosts": func() error {
			_, err := db.Hosts()

			return err
		},
		"State": func() error {
			_, _, err := db.State("/a.log")

			return err
		},
		"Unique": func() error {
			_, err := db.Unique("2000", Filter{}, "h")

			return err
		},
	} {
		if err := read(); !errors.Is(err, berrors.ErrDatabaseNotOpen) {
			t.Errorf("%s: err = %v, want ErrDatabaseNotOpen", name, err)
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

// A new store keeps the configured zone, else the system's. Reopened, it keeps that zone and refuses another. Local,
// localtime or a zone the system does not know is refused, whether configured, stored or the system's, and never kept.
func TestOpenZone(t *testing.T) {
	refused := []string{"Local", "localtime", "Nowhere/Nothing"}
	// Reports whether err refuses zone as it should: as each run's zone, unless the system does not know it.
	refuses := func(zone string, err error) bool {
		return err != nil && (zone == "Nowhere/Nothing" || errors.Is(err, errLocalZone))
	}

	for _, zone := range refused {
		t.Setenv("TZ", zone)

		if _, err := openZone(t, filepath.Join(t.TempDir(), "kirika.db"), ""); !refuses(zone, err) {
			t.Errorf("system zone %s: err = %v", zone, err)
		}
	}

	t.Setenv("TZ", "America/Sao_Paulo")

	path := filepath.Join(t.TempDir(), "kirika.db")
	for _, zone := range refused {
		if _, err := openZone(t, path, zone); !refuses(zone, err) {
			t.Errorf("configured zone %s: err = %v", zone, err)
		}
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

	for _, zone := range refused {
		setMeta(t, path, metaZone, []byte(zone))

		if _, err := openZone(t, path, ""); !refuses(zone, err) {
			t.Errorf("stored zone %s: err = %v", zone, err)
		}
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
