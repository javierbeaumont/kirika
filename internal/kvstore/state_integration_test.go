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
	"errors"
	"testing"

	berrors "go.etcd.io/bbolt/errors"
)

// Returns the stored state of the log at path, failing the test on error.
func logState(t *testing.T, db *DB, path string) (LogState, bool) {
	t.Helper()

	s, ok, err := db.State(path)
	if err != nil {
		t.Fatalf("State(%q): %v", path, err)
	}

	return s, ok
}

// A flush writes each log's latest state, even from a batch with no event, and a later flush keeps the states it does
// not set.
func TestState(t *testing.T) {
	db := openStore(t)

	if s, ok := logState(t, db, "/a.log"); ok {
		t.Fatalf("State before any flush = %+v", s)
	}

	b := db.NewBatch(DefaultOptions())
	b.SetState("/a.log", LogState{Line: 1, Offset: 10, Sum: [8]byte{1}})
	b.SetState("/a.log", LogState{Line: 2, Offset: 20, Sum: [8]byte{2}})
	b.SetState("/b.log", LogState{Line: 3, Offset: 30, Sum: [8]byte{3}})

	if err := db.Flush(b); err != nil {
		t.Fatalf("flush: %v", err)
	}

	if got, ok := logState(t, db, "/a.log"); !ok || got != (LogState{Line: 2, Offset: 20, Sum: [8]byte{2}}) {
		t.Errorf("State after a flush with no event = %+v, %v; want line 2", got, ok)
	}

	b.Apply(page("h", "/", 200, 1, base))
	b.SetState("/a.log", LogState{Line: 4, Offset: 40, Sum: [8]byte{4}})

	if err := db.Flush(b); err != nil {
		t.Fatalf("flush: %v", err)
	}

	for path, want := range map[string]LogState{
		"/a.log": {Line: 4, Offset: 40, Sum: [8]byte{4}},
		"/b.log": {Line: 3, Offset: 30, Sum: [8]byte{3}},
	} {
		if got, ok := logState(t, db, path); !ok || got != want {
			t.Errorf("State(%q) = %+v, %v; want %+v", path, got, ok, want)
		}
	}
}

// A state with no path fails the flush.
func TestStateNoPath(t *testing.T) {
	db := openStore(t)

	b := db.NewBatch(DefaultOptions())
	b.SetState("", LogState{Offset: 1})

	if err := db.Flush(b); !errors.Is(err, berrors.ErrKeyRequired) {
		t.Errorf("Flush: err = %v, want ErrKeyRequired", err)
	}
}

// An unreadable stored state is an error.
func TestStateCorrupt(t *testing.T) {
	db := openStore(t)
	putRaw(t, db, bktState, []byte("/a.log"), []byte{0})

	if _, ok, err := db.State("/a.log"); ok || !errors.Is(err, errBadState) {
		t.Errorf("State: ok = %v, err = %v; want errBadState", ok, err)
	}
}
