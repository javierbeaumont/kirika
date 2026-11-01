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

// Package kvstore is kirika's storage engine: one bbolt file.
package kvstore

import (
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
	berrors "go.etcd.io/bbolt/errors"
)

// schemaVersion is the store format this build writes.
const schemaVersion = 1

var (
	bktMeta    = []byte("meta")
	metaSchema = []byte("schema")
)

// Errors for a stored schema version this build refuses.
var (
	errSchemaCorrupt = errors.New("kvstore: corrupt schema version")
	errSchemaNewer   = errors.New("kvstore: store schema is newer than this build")
)

// DB is an open store. bbolt locks the file, so one process at a time holds it.
type DB struct {
	b *bolt.DB
}

// Open opens the store at path, creating it if missing. timeout bounds the wait for another process to release the file
// (0 waits forever). A store written by a newer build, or with a corrupt schema version, is refused.
func Open(path string, timeout time.Duration) (*DB, error) {
	b, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: timeout})
	if errors.Is(err, berrors.ErrTimeout) {
		return nil, fmt.Errorf("kvstore: open %s: another process holds it: %w", path, err)
	}

	if err != nil {
		return nil, fmt.Errorf("kvstore: open %s: %w", path, err)
	}

	db := &DB{b: b}
	if err := db.init(); err != nil {
		_ = b.Close()

		return nil, err
	}

	return db, nil
}

// Close releases the store and its lock.
func (db *DB) Close() error {
	return db.b.Close()
}

// init creates the meta bucket and writes the schema version, or checks the stored one.
func (db *DB) init() error {
	return db.b.Update(func(tx *bolt.Tx) error {
		meta, err := tx.CreateBucketIfNotExists(bktMeta)
		if err != nil {
			return err
		}

		switch v := meta.Get(metaSchema); {
		case v == nil:
			return meta.Put(metaSchema, []byte{schemaVersion})
		case len(v) != 1 || v[0] == 0:
			return fmt.Errorf("%w: %q", errSchemaCorrupt, v)
		case v[0] > schemaVersion:
			return fmt.Errorf("%w: v%d > v%d; upgrade kirika", errSchemaNewer, v[0], schemaVersion)
		}

		return nil
	})
}
