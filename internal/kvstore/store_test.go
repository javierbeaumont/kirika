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

// Writes a raw schema version into the store at path.
func setSchema(t *testing.T, path string, v []byte) {
	t.Helper()

	b, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatalf("bolt open: %v", err)
	}

	err = b.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bktMeta).Put(metaSchema, v)
	})
	if err != nil {
		t.Fatalf("set schema: %v", err)
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

	db, err := Open(path, time.Second)
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

	db, err := Open(path, time.Second)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	defer closeStore(t, db)

	err = db.b.View(func(tx *bolt.Tx) error {
		if tx.Bucket(bktAgg) == nil {
			t.Error("no agg bucket")
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
		if _, err := Open(path, time.Second); err == nil || errors.Is(err, berrors.ErrTimeout) {
			t.Errorf("Open(%s): err = %v, want an error other than the lock timeout", path, err)
		}
	}
}

func TestOpenLocked(t *testing.T) {
	path := storePath(t)

	db, err := Open(path, time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	if _, err := Open(path, 50*time.Millisecond); !errors.Is(err, berrors.ErrTimeout) {
		t.Errorf("second open: err = %v, want the lock timeout", err)
	}

	closeStore(t, db)

	db, err = Open(path, time.Second)
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
		setSchema(t, path, tc.v)

		for _, timeout := range []time.Duration{time.Second, 50 * time.Millisecond} {
			db, err := Open(path, timeout)
			if err == nil {
				closeStore(t, db)
			}

			if !errors.Is(err, tc.want) {
				t.Errorf("schema %q, timeout %v: err = %v, want %v", tc.v, timeout, err, tc.want)
			}
		}
	}
}
