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
	"os"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
	berrors "go.etcd.io/bbolt/errors"
)

// The store format this build writes.
const schemaVersion = 1

var (
	bktAgg     = []byte("agg")
	bktMeta    = []byte("meta")
	bktSess    = []byte("sess")
	bktState   = []byte("state")
	bktUniq    = []byte("uniq")
	metaSalt   = []byte("salt")
	metaSchema = []byte("schema")
	metaZone   = []byte("zone")
)

// Errors for a stored schema version this build refuses.
var (
	errSchemaCorrupt = errors.New("kvstore: corrupt schema version")
	errSchemaNewer   = errors.New("kvstore: store schema is newer than this build")
	errZone          = errors.New("kvstore: the store keeps another time zone")
)

// DB is an open store. bbolt locks the file, so one process at a time holds it.
type DB struct {
	b    *bolt.DB
	loc  *time.Location // the zone of its hours, days and months
	salt []byte         // the key of its session IDs
}

// Open opens the store at path, creating it if missing. timeout bounds the wait for another process to release the file
// (0 waits forever). zone names the time zone of its hours, days and months, such as America/New_York. When empty, it
// is the zone the store keeps or, for a new store, the system's, else UTC. A store written by a newer build or with a
// corrupt schema version or salt is refused, and so is a zone the system does not know or other than the stored one.
func Open(path string, timeout time.Duration, zone string) (*DB, error) {
	b, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: timeout})
	if errors.Is(err, berrors.ErrTimeout) {
		return nil, fmt.Errorf("kvstore: open %s: another process holds it: %w", path, err)
	}

	if err != nil {
		return nil, fmt.Errorf("kvstore: open %s: %w", path, err)
	}

	db := &DB{b: b}
	if err := db.init(zone); err != nil {
		_ = b.Close()

		return nil, err
	}

	return db, nil
}

// Zone returns the name of the store's time zone.
func (db *DB) Zone() string {
	return db.loc.String()
}

// Close releases the store and its lock.
func (db *DB) Close() error {
	return db.b.Close()
}

// Creates the buckets and writes the schema version, the time zone and the salt, or checks the stored ones.
func (db *DB) init(zone string) error {
	return db.b.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{bktAgg, bktSess, bktState, bktUniq} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}

		meta, err := tx.CreateBucketIfNotExists(bktMeta)
		if err != nil {
			return err
		}

		switch v := meta.Get(metaSchema); {
		case v == nil:
			if err := meta.Put(metaSchema, []byte{schemaVersion}); err != nil {
				return err
			}
		case len(v) != 1 || v[0] == 0:
			return fmt.Errorf("%w: %q", errSchemaCorrupt, v)
		case v[0] > schemaVersion:
			return fmt.Errorf("%w: v%d > v%d; upgrade kirika", errSchemaNewer, v[0], schemaVersion)
		}

		stored := string(meta.Get(metaZone))
		switch {
		case stored == "" && zone == "":
			zone = systemZone(os.LookupEnv, os.Readlink, readText)
		case zone == "":
			zone = stored
		case stored != "" && zone != stored:
			return fmt.Errorf("%w: %s, not %s", errZone, stored, zone)
		}

		loc, err := time.LoadLocation(zone)
		if err != nil {
			return fmt.Errorf("kvstore: %w", err)
		}

		db.loc = loc

		if stored == "" {
			if err := meta.Put(metaZone, []byte(zone)); err != nil {
				return err
			}
		}

		return db.loadSalt(meta)
	})
}

// Returns the name of the system's time zone. TZ names it when set, an empty one meaning UTC; a leading ":" is dropped,
// and a path in TZ names the zone it links to. Without TZ, that path is /etc/localtime, and a copy there is named by
// /etc/timezone or /var/db/zoneinfo. Else the zone is UTC.
func systemZone(getenv func(string) (string, bool), readlink, readFile func(string) (string, error)) string {
	file := "/etc/localtime"

	if tz, ok := getenv("TZ"); ok {
		tz = strings.TrimPrefix(tz, ":")
		switch {
		case tz == "":
			return "UTC"
		case !strings.HasPrefix(tz, "/"):
			return tz
		}

		file = tz
	}

	if name, ok := zoneinfoName(file); ok {
		return name
	}

	if target, err := readlink(file); err == nil {
		if name, ok := zoneinfoName(target); ok {
			return name
		}
	}

	if file == "/etc/localtime" {
		for _, named := range []string{"/etc/timezone", "/var/db/zoneinfo"} {
			if text, err := readFile(named); err == nil {
				if name := strings.TrimSpace(text); name != "" {
					return name
				}
			}
		}
	}

	return "UTC"
}

// Returns the zone name in a path under a zoneinfo directory.
func zoneinfoName(path string) (string, bool) {
	_, name, found := strings.Cut(path, "zoneinfo/")

	return name, found
}

// Returns the contents of the file at path.
func readText(path string) (string, error) {
	b, err := os.ReadFile(path)

	return string(b), err
}
