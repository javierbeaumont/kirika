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

package ingest

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/javierbeaumont/kirika/internal/kvstore"
	"github.com/javierbeaumont/kirika/internal/logparse"
	bolt "go.etcd.io/bbolt"
)

// Returns a store in a fresh directory, closed when the test ends.
func openStore(t *testing.T) *kvstore.DB {
	t.Helper()

	db, err := kvstore.Open(filepath.Join(t.TempDir(), "kirika.db"), time.Second, "UTC")
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})

	return db
}

// Returns an NCSA Combined line of a request by client for path with method, answered with 200 at tm.
func ncsa(client, method, path string, tm time.Time) string {
	return fmt.Sprintf("%s - - [%s] \"%s %s HTTP/1.1\" 200 1 \"-\" \"Mozilla/5.0 (X11; Linux x86_64)\"", client,
		tm.Format("02/Jan/2006:15:04:05 -0700"), method, path)
}

// Returns n lines of GET requests from distinct clients at base, each with its newline, the first from client first.
func gets(first, n int) string {
	var b strings.Builder
	for i := first; i < first+n; i++ {
		b.WriteString(ncsa(fmt.Sprintf("10.0.%d.%d", i>>8&255, i&255), "GET", "/", base) + "\n")
	}

	return b.String()
}

// Writes text as the whole log at path.
func writeLog(t *testing.T, path, text string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// Appends text to the log at path.
func appendLog(t *testing.T, path, text string) {
	t.Helper()

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}

	if _, err := f.WriteString(text); err != nil {
		t.Fatalf("append to %s: %v", path, err)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", path, err)
	}
}

// Returns a reader of the NCSA log at path into db, with the default options, the default host h and the clock at base.
func reader(t *testing.T, db *kvstore.DB, path string) *Reader {
	t.Helper()

	o := DefaultOptions()
	o.DefaultHost = "h"
	o.Now = func() time.Time { return base }

	r, err := New(db, path, logparse.ParseNCSA, o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return r
}

// Reads r, failing the test on error.
func read(t *testing.T, r *Reader) Result {
	t.Helper()

	res, err := r.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	return res
}

// Returns the hits of host h in 2000.
func hits(t *testing.T, db *kvstore.DB) int64 {
	t.Helper()

	c, err := db.Totals("h", "2000", kvstore.Filter{})
	if err != nil {
		t.Fatalf("Totals: %v", err)
	}

	return c.Hits
}

// A read counts each new line once, under the default host: the next one goes on after the last line read, and finds
// nothing until the log grows.
func TestRead(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 3))
	r := reader(t, db, path)

	for _, tc := range []struct {
		grow string
		want Result
		hits int64
	}{
		{"", Result{Counted: 3}, 3},
		{"", Result{}, 3},
		{gets(3, 2), Result{Counted: 2}, 5},
		{"", Result{}, 5},
	} {
		appendLog(t, path, tc.grow)

		if got := read(t, r); got != tc.want || hits(t, db) != tc.hits {
			t.Errorf("after %d more bytes: %+v, %d hits; want %+v, %d", len(tc.grow), got, hits(t, db), tc.want,
				tc.hits)
		}
	}
}

// A log the path holds anew is read from its start, whether it grew past the old offset, is shorter or is empty, and so
// is a log in the place of a missing one.
func TestNewLog(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	r := reader(t, db, path)

	if _, err := r.Read(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Read of a missing log: %v, want os.ErrNotExist", err)
	}

	for _, tc := range []struct {
		log  string
		want int
	}{
		{gets(0, 3), 3},
		{gets(100, 5), 5},
		{gets(200, 1), 1},
		{"", 0},
		{gets(300, 2), 2},
	} {
		writeLog(t, path, tc.log)

		if got := read(t, r); got.Counted != tc.want {
			t.Errorf("a new log of %d bytes: %d lines counted, want %d", len(tc.log), got.Counted, tc.want)
		}
	}

	if got := hits(t, db); got != 11 {
		t.Errorf("hits = %d, want 11", got)
	}
}

// A last line with no newline waits for the next read, and then counts once.
func TestPartialLine(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	whole := gets(1, 1)
	writeLog(t, path, gets(0, 1)+whole[:20])
	r := reader(t, db, path)

	if got := read(t, r); got != (Result{Counted: 1}) {
		t.Errorf("Read with a line cut = %+v, want 1 counted", got)
	}

	appendLog(t, path, whole[20:])

	if got := read(t, r); got != (Result{Counted: 1}) || hits(t, db) != 2 {
		t.Errorf("Read of the rest = %+v, %d hits; want 1 counted, 2 hits", got, hits(t, db))
	}
}

// A log whose lines end with CRLF reads and resumes as one with LF.
func TestCRLF(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	crlf := func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }
	writeLog(t, path, crlf(gets(0, 2)))
	r := reader(t, db, path)
	read(t, r)
	appendLog(t, path, crlf(gets(2, 1)))

	if got := read(t, r); got != (Result{Counted: 1}) || hits(t, db) != 3 {
		t.Errorf("Read after CRLF lines = %+v, %d hits; want 1 counted, 3 hits", got, hits(t, db))
	}
}

// A read that ends on a line longer than 1 MiB goes on after it.
func TestLongLastLine(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 1)+strings.Repeat("x", maxLine+1)+"\n")
	r := reader(t, db, path)

	if got := read(t, r); got != (Result{Counted: 1, TooLong: 1}) {
		t.Errorf("first Read = %+v, want 1 counted and 1 too long", got)
	}

	appendLog(t, path, gets(1, 1))

	if got := read(t, r); got != (Result{Counted: 1}) {
		t.Errorf("next Read = %+v, want 1 counted", got)
	}
}

// Each line not counted adds to its own counter and is told at debug level with its offset and reason, never with its
// content.
func TestReasons(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	lines := []string{
		ncsa("192.0.2.1", "GET", "/", base),
		"",
		"\x00" + ncsa("192.0.2.1", "GET", "/", base),
		strings.Repeat("x", maxLine+1),
		"192.0.2.1 garbage",
		ncsa("192.0.2.1", "TRACE", "/", base),
		ncsa("192.0.2.1", "GET", "/", base.Add(ahead)),
		ncsa("192.0.2.1", "GET", "/", base.Add(ahead+time.Second)),
		ncsa("192.0.2.1", "GET", "/", base.AddDate(-1001, 0, 0)),
	}
	writeLog(t, path, strings.Join(lines, "\n")+"\n")

	var logged bytes.Buffer

	o := DefaultOptions()
	o.Log = slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug}))
	o.Now = func() time.Time { return base }

	r, err := New(db, path, logparse.ParseNCSA, o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	want := Result{Counted: 2, Blank: 1, Dropped: 1, Malformed: 1, Binary: 1, TooLong: 1, BadDate: 2}
	if got := read(t, r); got != want {
		t.Errorf("Read = %+v, want %+v", got, want)
	}

	off := 0
	for i, l := range lines {
		if i != 0 && i != 6 && !strings.Contains(logged.String(), fmt.Sprintf("line=%d offset=%d ", i+1, off)) {
			t.Errorf("no report of line %d at offset %d", i+1, off)
		}

		off += len(l) + 1
	}

	for _, reason := range []string{
		"blank", "binary", "longer than 1 MiB", "malformed", "method not counted",
		"dated more than 24 hours ahead or before the year 1000", "method=TRACE", "error=",
	} {
		if !strings.Contains(logged.String(), reason) {
			t.Errorf("no report says %q", reason)
		}
	}

	if strings.Contains(logged.String(), "192.0.2.1") {
		t.Error("a report holds a client address")
	}
}

// A line keeps its number from the start of its log across reads, in the reports and the state, and a new log numbers
// its lines from 1 again.
func TestLineNumbers(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 2))

	var logged bytes.Buffer

	o := DefaultOptions()
	o.Log = slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug}))
	o.Now = func() time.Time { return base }

	r, err := New(db, path, logparse.ParseNCSA, o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, tc := range []struct {
		name, log string
		grow      bool
		bad, last int64
	}{
		{"the first read", "", true, 0, 2},
		{"the next read", "garbage\n", true, 3, 3},
		{"a new log", "garbage\n" + gets(5, 1), false, 1, 2},
	} {
		logged.Reset()

		if tc.grow {
			appendLog(t, path, tc.log)
		} else {
			writeLog(t, path, tc.log)
		}

		read(t, r)

		if tc.bad != 0 && !strings.Contains(logged.String(), fmt.Sprintf("line=%d ", tc.bad)) {
			t.Errorf("%s: no report of line %d in %q", tc.name, tc.bad, logged.String())
		}

		if s, _, err := db.State(r.path); err != nil || s.Line != tc.last {
			t.Errorf("%s: state at line %d, %v; want %d", tc.name, s.Line, err, tc.last)
		}
	}
}

// 50 unreadable lines in a row, across reads, stop a read before it writes anything, and the next read stops again on
// them. Blank lines neither add to the row nor break it; a counted or dropped line breaks it.
func TestUnreadableRun(t *testing.T) {
	bad := func(n int) string { return strings.Repeat("garbage\n", n) }

	for _, tc := range []struct {
		name  string
		reads []string
		fails bool
	}{
		{"49", []string{bad(49) + gets(0, 1)}, false},
		{"50", []string{bad(50) + gets(0, 1)}, true},
		{"50 after a counted line", []string{gets(0, 1) + bad(50)}, true},
		{"blank lines inside", []string{bad(25) + "\n\n" + bad(25)}, true},
		{"a counted line inside", []string{bad(25) + gets(0, 1) + bad(25)}, false},
		{"a dropped line inside", []string{bad(25) + ncsa("10.0.0.1", "TRACE", "/", base) + "\n" + bad(25)}, false},
		{"across reads", []string{bad(30), bad(20)}, true},
		{"across reads, broken", []string{bad(30), gets(0, 1) + bad(20)}, false},
	} {
		db := openStore(t)
		path := filepath.Join(t.TempDir(), "access.log")
		writeLog(t, path, "")
		r := reader(t, db, path)

		for _, text := range tc.reads[:len(tc.reads)-1] {
			appendLog(t, path, text)
			read(t, r)
		}

		before, _, _ := db.State(r.path)
		hitsBefore := hits(t, db)
		appendLog(t, path, tc.reads[len(tc.reads)-1])

		_, err := r.Read()
		if !tc.fails {
			if err != nil {
				t.Errorf("%s: %v", tc.name, err)
			}

			continue
		}

		if !errors.Is(err, ErrUnreadable) {
			t.Errorf("%s: %v, want ErrUnreadable", tc.name, err)
		}

		if _, err := r.Read(); !errors.Is(err, ErrUnreadable) {
			t.Errorf("%s: the next read: %v, want ErrUnreadable", tc.name, err)
		}

		if after, _, _ := db.State(r.path); after != before || hits(t, db) != hitsBefore {
			t.Errorf("%s: the stopped reads wrote: state %+v, then %+v", tc.name, before, after)
		}
	}
}

// Writes v under key into the bucket bkt of the store at store, which must be closed.
func putRaw(t *testing.T, store, bkt, key string, v []byte) {
	t.Helper()

	b, err := bolt.Open(store, 0o600, nil)
	if err != nil {
		t.Fatalf("bolt open: %v", err)
	}

	err = b.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte(bkt)).Put([]byte(key), v) })
	if err != nil {
		t.Fatalf("put: %v", err)
	}

	if err := b.Close(); err != nil {
		t.Fatalf("bolt close: %v", err)
	}
}

// A read fails on a log state it cannot use: unreadable, or with a negative offset.
func TestBadState(t *testing.T) {
	for name, v := range map[string][]byte{
		"unreadable":      []byte("bad"),
		"negative offset": append([]byte{1, 2, 1}, make([]byte, 8)...), // version 1, line 1, offset -1
	} {
		dir := t.TempDir()
		store, path := filepath.Join(dir, "kirika.db"), filepath.Join(dir, "access.log")
		writeLog(t, path, gets(0, 1))

		db, err := kvstore.Open(store, time.Second, "UTC")
		if err != nil {
			t.Fatalf("open: %v", err)
		}

		if err := db.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}

		putRaw(t, store, "state", path, v)

		db, err = kvstore.Open(store, time.Second, "UTC")
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}

		if _, err := reader(t, db, path).Read(); err == nil {
			t.Errorf("Read with a state %s: no error", name)
		}

		if err := db.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	}
}

// A read whose flush fails returns the store's error.
func TestFlushError(t *testing.T) {
	dir := t.TempDir()
	store, path := filepath.Join(dir, "kirika.db"), filepath.Join(dir, "access.log")
	writeLog(t, path, gets(0, 1))

	db, err := kvstore.Open(store, time.Second, "UTC")
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// The day key of host h on 2000-01-01, as kvstore lays it out, with a value no tally reads.
	putRaw(t, store, "agg", "\x02td\x01h20000101", []byte{0})

	db, err = kvstore.Open(store, time.Second, "UTC")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	t.Cleanup(func() { _ = db.Close() })

	if _, err := reader(t, db, path).Read(); err == nil {
		t.Error("Read onto a corrupt store: no error")
	}
}

// A read of a path that is a directory fails, whether or not the path has a state.
func TestDirectory(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 1))
	r := reader(t, db, path)
	read(t, r)

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}

	for _, dir := range []string{path, t.TempDir()} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}

		if _, err := reader(t, db, dir).Read(); err == nil {
			t.Errorf("Read of the directory %s: no error", dir)
		}
	}
}

// A relative path names the same log, and so the same state, as its absolute form.
func TestRelativePath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	db := openStore(t)
	writeLog(t, "access.log", gets(0, 2))
	read(t, reader(t, db, "access.log"))

	if got := read(t, reader(t, db, filepath.Join(dir, "access.log"))); got != (Result{}) {
		t.Errorf("Read by the absolute path = %+v, want nothing new", got)
	}
}

// The counting rules of the options reach the store: with 404 the only valid code, a 200 is another status.
func TestCountOptions(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 1))

	o := DefaultOptions()
	o.Count.ValidCodes = []int{404}
	o.DefaultHost = "h"
	o.Now = func() time.Time { return base }

	r, err := New(db, path, logparse.ParseNCSA, o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	read(t, r)

	if got := hits(t, db); got != 0 {
		t.Errorf("hits of correct requests = %d, want 0", got)
	}

	if c, err := db.Totals("h", "2000", kvstore.Filter{Status: kvstore.AllStatuses}); err != nil || c.Hits != 1 {
		t.Errorf("hits of every status = %d, %v; want 1", c.Hits, err)
	}
}

// Without a clock, a read measures the 24 hours a line may be ahead from the time it runs.
func TestClock(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	now := time.Now()
	writeLog(t, path, ncsa("10.0.0.1", "GET", "/", now)+"\n"+ncsa("10.0.0.2", "GET", "/", now.Add(2*ahead))+"\n")

	r, err := New(db, path, logparse.ParseNCSA, DefaultOptions())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if got := read(t, r); got != (Result{Counted: 1, BadDate: 1}) {
		t.Errorf("Read = %+v, want 1 counted and 1 dated ahead", got)
	}
}
