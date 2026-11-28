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
	bktKeys    = []byte("keys")
	bktMeta    = []byte("meta")
	bktSess    = []byte("sess")
	bktState   = []byte("state")
	bktUniq    = []byte("uniq")
	metaClosed = []byte("closed")
	metaSalt   = []byte("salt")
	metaSchema = []byte("schema")
	metaZone   = []byte("zone")
)

// Errors Open returns.
var (
	errLocalZone = errors.New("kvstore: Local and localtime are each run's zone; " +
		"a store needs a named one, such as Europe/Madrid")
	errNotStore      = errors.New("kvstore: not a kirika store: it holds buckets but no schema version")
	errSchemaCorrupt = errors.New("kvstore: corrupt schema version")
	errSchemaNewer   = errors.New("kvstore: store schema is newer than this build")
)

// DB is an open store. bbolt locks the file, so one process at a time holds it.
type DB struct {
	file         *bolt.DB
	location     *time.Location // the zone of its hours, days and months
	replacedZone string         // the zone Open replaced, else ""
	salt         []byte         // the key of its session IDs
}

// Open opens the store at path, creating it if missing. timeout bounds each wait for another process to release the
// file, one to read it and one to write it (0 waits forever). zone names the time zone of its hours, days and months,
// such as America/New_York; one other than the store's replaces it, and what the store counted stays in the zone it was
// counted in. When empty, it is the zone the store keeps or, for a new store, the system's, else UTC. A zone of the tz
// database's posix/ or right/ copies counts without that prefix. A file with buckets but no schema version, such as
// another program's, is refused before anything is written, and so is a store written by a newer build or with a
// corrupt schema version. A corrupt salt is refused too, and so is a zone the system does not know or one that is each
// run's: Local, and localtime, which Debian links to /etc/localtime.
func Open(path string, timeout time.Duration, zone string) (*DB, error) {
	if err := probe(path, timeout); err != nil {
		return nil, err
	}

	file, err := openFile(path, &bolt.Options{Timeout: timeout})
	if err != nil {
		return nil, err
	}

	db := &DB{file: file}
	if err := db.init(zone); err != nil {
		_ = file.Close()

		return nil, err
	}

	return db, nil
}

// Returns why Open refuses the file at path, opened only to read: bbolt writes to some files it opens to write, such as
// one saved without its free-page list. A path that is missing or cannot be stat'ed, or an empty file, is left to the
// open that writes.
func probe(path string, timeout time.Duration) error {
	if info, err := os.Stat(path); err != nil || info.Size() == 0 {
		return nil
	}

	file, err := openFile(path, &bolt.Options{ReadOnly: true, Timeout: timeout})
	if err != nil {
		return err
	}

	return errors.Join(file.View(checkSchema), file.Close())
}

// Opens the bbolt file at path with options.
func openFile(path string, options *bolt.Options) (*bolt.DB, error) {
	file, err := bolt.Open(path, 0o600, options)
	if errors.Is(err, berrors.ErrTimeout) {
		return nil, fmt.Errorf("kvstore: open %s: another process holds it: %w", path, err)
	}

	if err != nil {
		return nil, fmt.Errorf("kvstore: open %s: %w", path, err)
	}

	return file, nil
}

// Location returns the store's time zone.
func (db *DB) Location() *time.Location {
	return db.location
}

// ReplacedZone returns the name of the time zone Open replaced, else "".
func (db *DB) ReplacedZone() string {
	return db.replacedZone
}

// Close releases the store and its lock.
func (db *DB) Close() error {
	return db.file.Close()
}

// Checks the schema version, then creates the missing buckets and writes the schema version and the salt, or checks the
// stored ones. Writes the time zone when it is new or replaced.
func (db *DB) init(zone string) error {
	return db.file.Update(func(tx *bolt.Tx) error {
		if err := checkSchema(tx); err != nil {
			return err
		}

		for _, name := range [][]byte{bktAgg, bktKeys, bktMeta, bktSess, bktState, bktUniq} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}

		meta := tx.Bucket(bktMeta)
		if meta.Get(metaSchema) == nil {
			if err := meta.Put(metaSchema, []byte{schemaVersion}); err != nil {
				return err
			}
		}

		stored := plainZone(string(meta.Get(metaZone)))
		zone = plainZone(zone)

		switch {
		case stored == "" && zone == "":
			zone = plainZone(systemZone(os.LookupEnv, os.Readlink, readText))
		case zone == "":
			zone = stored
		}

		if zone == "Local" || zone == "localtime" {
			return errLocalZone
		}

		location, err := time.LoadLocation(zone)
		if err != nil {
			return fmt.Errorf("kvstore: %w", err)
		}

		db.location = location

		if zone != stored {
			if err := meta.Put(metaZone, []byte(zone)); err != nil {
				return err
			}

			db.replacedZone = stored
		}

		return db.loadSalt(meta)
	})
}

// Returns why Open refuses the file tx reads, if it does: buckets but no schema version, or a corrupt or newer one. A
// file with no bucket is a new store.
func checkSchema(tx *bolt.Tx) error {
	var version []byte
	if meta := tx.Bucket(bktMeta); meta != nil {
		version = meta.Get(metaSchema)
	}

	switch {
	case version == nil:
		if bucket, _ := tx.Cursor().First(); bucket != nil {
			return errNotStore
		}
	case len(version) != 1 || version[0] == 0:
		return fmt.Errorf("%w: %q", errSchemaCorrupt, version)
	case version[0] > schemaVersion:
		return fmt.Errorf("%w: v%d > v%d; upgrade kirika", errSchemaNewer, version[0], schemaVersion)
	}

	return nil
}

// Returns the name of the system's time zone. TZ names it when set, an empty one meaning UTC; a leading ":" is dropped,
// and a path in TZ names the zone it is or links to. Without TZ, that path is /etc/localtime; when it names no zone,
// /etc/timezone or /var/db/zoneinfo does. Else the zone is UTC.
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

// Returns the zone name in a path under a zoneinfo directory; the directory itself names none.
func zoneinfoName(path string) (name string, ok bool) {
	_, name, found := strings.Cut(path, "zoneinfo/")

	return name, found && name != ""
}

// Returns zone without a leading posix/ or right/, which name the tz database's two copies of its zones. The posix/
// ones are the same; Go skips the leap seconds the right/ ones count, so each change of offset falls as many seconds
// late as leap seconds came before it. Either prefix alone is kept: emptied, it would pass as no zone.
func plainZone(zone string) string {
	for _, prefix := range []string{"posix/", "right/"} {
		if name, ok := strings.CutPrefix(zone, prefix); ok && name != "" {
			return name
		}
	}

	return zone
}

// Returns the contents of the file at path.
func readText(path string) (string, error) {
	b, err := os.ReadFile(path)

	return string(b), err
}
