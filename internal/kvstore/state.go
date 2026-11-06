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
	"encoding/binary"
	"errors"

	bolt "go.etcd.io/bbolt"
)

// The format of a log state value this build writes.
const stateVersion = 1

var errBadState = errors.New("kvstore: corrupt or unknown log state")

// LogState is where reading a log stopped: the number and offset of the last line read, and a checksum of that line,
// which tells whether the path still holds that log.
type LogState struct {
	Line   int64 // counted from 1
	Offset int64
	Sum    [8]byte
}

// SetState sets the state of the log at path, which DB.Flush writes with the batch.
func (b *Batch) SetState(path string, s LogState) {
	b.state[path] = s
}

// State returns the stored state of the log at path; ok is false when it has none. An unreadable state is an error,
// since reading the log again would count it twice.
func (db *DB) State(path string) (s LogState, ok bool, err error) {
	err = db.b.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bktState).Get([]byte(path))
		if v == nil {
			return nil
		}

		s, ok = decodeState(v)
		if !ok {
			return errBadState
		}

		return nil
	})

	return s, ok, err
}

// Puts each log state under its path, in place of the stored one.
func writeState(bkt *bolt.Bucket, state map[string]LogState) error {
	for path, s := range state {
		if err := bkt.Put([]byte(path), encodeState(s)); err != nil {
			return err
		}
	}

	return nil
}

// Writes s as its format version, its line and its offset as varints, then its checksum.
func encodeState(s LogState) []byte {
	b := binary.AppendVarint([]byte{stateVersion}, s.Line)
	b = binary.AppendVarint(b, s.Offset)

	return append(b, s.Sum[:]...)
}

// Reads a value written by encodeState; for anything else, ok is false.
func decodeState(b []byte) (s LogState, ok bool) {
	if len(b) == 0 || b[0] != stateVersion {
		return LogState{}, false
	}

	line, n := binary.Varint(b[1:])
	if n <= 0 {
		return LogState{}, false
	}

	off, m := binary.Varint(b[1+n:])
	if m <= 0 || len(b) != 1+n+m+len(s.Sum) {
		return LogState{}, false
	}

	s.Line, s.Offset = line, off
	copy(s.Sum[:], b[1+n+m:])

	return s, true
}
