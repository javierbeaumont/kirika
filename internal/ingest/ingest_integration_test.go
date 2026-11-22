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
	"context"
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
	"github.com/javierbeaumont/kirika/internal/uaclass"
	bolt "go.etcd.io/bbolt"
)

// Returns a store in UTC.
func openStore(t *testing.T) *kvstore.DB {
	t.Helper()

	return openZone(t, "UTC")
}

// Returns a store in zone in a fresh directory, closed when the test ends.
func openZone(t *testing.T, zone string) *kvstore.DB {
	t.Helper()

	db, err := kvstore.Open(filepath.Join(t.TempDir(), "kirika.db"), time.Second, zone)
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

// Returns the reader New returns, closed when the test ends.
func newReader(t *testing.T, db *kvstore.DB, path string, parse logparse.Parser, options Options) *Reader {
	t.Helper()

	logReader, err := New(db, path, parse, options)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t.Cleanup(func() {
		if err := logReader.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	return logReader
}

// Returns a reader of the NCSA log at path into db, with the default options, the default host h and the clock at base.
func reader(t *testing.T, db *kvstore.DB, path string) *Reader {
	t.Helper()

	options := DefaultOptions()
	options.DefaultHost = "h"
	options.Now = func() time.Time { return base }

	return newReader(t, db, path, logparse.ParseNCSA, options)
}

// Returns a reader as reader does, but parsing with parse and logging to logged at info level.
func loggedReader(t *testing.T, db *kvstore.DB, path string, parse logparse.Parser, logged *bytes.Buffer) *Reader {
	t.Helper()

	options := DefaultOptions()
	options.DefaultHost = "h"
	options.Log = slog.New(slog.NewTextHandler(logged, nil))
	options.Now = func() time.Time { return base }

	return newReader(t, db, path, parse, options)
}

// Returns the logged warning that the log at path has no access line yet.
func noAccessWarning(path string) string {
	return `level=WARN msg="no access line yet, so each read starts the log over" path=` + path + "\n"
}

// Reads r, failing the test on error.
func read(t *testing.T, r *Reader) Result {
	t.Helper()

	res, err := r.Read(t.Context())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	return res
}

// A read tells how many of its counted lines are pages with a client of a year the store had closed before it: none of
// a year it closes itself, nor of the year after the last closed one.
func TestClosedYearPages(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 3)+ncsa("192.0.2.1", "GET", "/", base.AddDate(1, 1, 0))+"\n")

	options := DefaultOptions()
	options.Now = func() time.Time { return base.AddDate(1, 1, 0) }
	logReader := newReader(t, db, path, logparse.ParseNCSA, options)

	if got := read(t, logReader); got != (Result{Counted: 4}) {
		t.Errorf("Read = %+v, want 4 counted, no page of a closed year", got)
	}

	appendLog(t, path, gets(3, 3)+ncsa("192.0.2.2", "GET", "/", base.AddDate(1, 0, 0))+"\n"+
		ncsa("192.0.2.1", "GET", "/logo.png", base)+"\n")

	if got := read(t, logReader); got != (Result{Counted: 5, ClosedYearPages: 3}) {
		t.Errorf("Read = %+v, want 5 counted, 3 pages of a closed year", got)
	}
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

	if _, err := r.Read(t.Context()); !errors.Is(err, os.ErrNotExist) {
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

	options := DefaultOptions()
	options.Log = slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug}))
	options.Now = func() time.Time { return base }

	logReader := newReader(t, db, path, logparse.ParseNCSA, options)

	want := Result{Counted: 2, Blank: 1, Dropped: 1, Malformed: 1, Binary: 1, TooLong: 1, BadDate: 2}
	if got := read(t, logReader); got != want {
		t.Errorf("Read = %+v, want %+v", got, want)
	}

	offset := 0
	for i, text := range lines {
		if i != 0 && i != 6 && !strings.Contains(logged.String(), fmt.Sprintf("line=%d offset=%d ", i+1, offset)) {
			t.Errorf("no report of line %d at offset %d", i+1, offset)
		}

		offset += len(text) + 1
	}

	for _, reason := range []string{
		"blank", "binary", "longer than 1 MiB", "malformed", "method not counted",
		"dated more than 24 hours ahead or out of years 1000-9999", "method=TRACE", "error=",
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

	options := DefaultOptions()
	options.Log = slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug}))
	options.Now = func() time.Time { return base }

	logReader := newReader(t, db, path, logparse.ParseNCSA, options)

	for _, tc := range []struct {
		name, log         string
		grow              bool
		badLine, lastLine int64
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

		read(t, logReader)

		if tc.badLine != 0 && !strings.Contains(logged.String(), fmt.Sprintf("line=%d ", tc.badLine)) {
			t.Errorf("%s: no report of line %d in %q", tc.name, tc.badLine, logged.String())
		}

		if state, _, err := db.State(logReader.path); err != nil || state.Line != tc.lastLine {
			t.Errorf("%s: state at line %d, %v; want %d", tc.name, state.Line, err, tc.lastLine)
		}
	}
}

// The first read of a path fails and writes nothing when it finds an unreadable line and none counted or dropped, and
// its error names the first unreadable line and why. Blank lines are neither: with only them, it warns.
func TestFirstRead(t *testing.T) {
	const refused = "ingest: no readable line in the first read of a log; "

	for _, tc := range []struct {
		name, log, err string
		state, warned  bool
	}{
		{"empty", "", "", false, false},
		{"blank", "\n\n", "", false, true},
		{
			"malformed", "\ngarbage\n\x00\n", refused + "line 2 is malformed: ncsa: ident is missing at offset 7",
			false, false,
		},
		{"binary", "\x00\n", refused + "line 1 is binary", false, false},
		{"too long", strings.Repeat("x", maxLine+1) + "\n", refused + "line 1 is longer than 1 MiB", false, false},
		{
			"dated ahead", ncsa("192.0.2.1", "GET", "/", base.Add(2*ahead)) + "\n",
			refused + "line 1 is dated more than 24 hours ahead or out of years 1000-9999", false, false,
		},
		{"malformed and a counted one", "garbage\n" + gets(0, 1), "", true, false},
		{"malformed and a dropped one", "garbage\n" + ncsa("192.0.2.1", "TRACE", "/", base) + "\n", "", true, false},
	} {
		db := openStore(t)
		path := filepath.Join(t.TempDir(), "access.log")
		writeLog(t, path, tc.log)

		var logged bytes.Buffer

		_, err := loggedReader(t, db, path, logparse.ParseNCSA, &logged).Read(t.Context())
		if got := fmt.Sprint(err); tc.err == "" && err != nil || tc.err != "" && (got != tc.err ||
			!errors.Is(err, ErrUnreadable)) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.err)
		}

		if _, ok, err := db.State(path); err != nil || ok != tc.state {
			t.Errorf("%s: a state %v, %v; want %v", tc.name, ok, err, tc.state)
		}

		if warned := strings.Contains(logged.String(), noAccessWarning(path)); warned != tc.warned {
			t.Errorf("%s: warned %v, want %v", tc.name, warned, tc.warned)
		}
	}
}

// A first read that writes nothing leaves the path without a state, and the next one reads the log from its start:
// after blank lines, an unreadable one fails it, and a readable one then counts.
func TestFirstReadAgain(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, "\n")
	r := reader(t, db, path)

	if got := read(t, r); got != (Result{Blank: 1}) {
		t.Errorf("Read of a blank line = %+v, want 1 blank", got)
	}

	appendLog(t, path, "garbage\n")

	if got, err := r.Read(t.Context()); got != (Result{Blank: 1, Malformed: 1}) || !errors.Is(err, ErrUnreadable) {
		t.Errorf("Read of an unreadable line = %+v, %v; want 1 blank, 1 malformed and ErrUnreadable", got, err)
	}

	appendLog(t, path, gets(0, 1))

	if got := read(t, r); got != (Result{Counted: 1, Blank: 1, Malformed: 1}) || hits(t, db) != 1 {
		t.Errorf("Read of a readable line = %+v, %d hits; want 1 counted, 1 blank, 1 malformed, 1 hit", got,
			hits(t, db))
	}
}

// A first read of entries that are not accesses, as in Caddy's runtime log, writes nothing and warns. Later reads warn
// no more and start the log over until one counts an access line.
func TestFirstReadNotAccess(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "caddy.log")
	runtimeEntry := `{"level":"info","logger":"tls","msg":"cleaning storage unit"}` + "\n"
	writeLog(t, path, runtimeEntry)

	var logged bytes.Buffer

	logReader := loggedReader(t, db, path, logparse.ParseCaddyJSON, &logged)

	if got := read(t, logReader); got != (Result{NotAccess: 1}) {
		t.Errorf("first read = %+v, want 1 not an access", got)
	}

	appendLog(t, path, runtimeEntry)

	if got := read(t, logReader); got != (Result{NotAccess: 2}) {
		t.Errorf("second read = %+v, want 2 not an access", got)
	}

	appendLog(t, path, `{"ts":946684800,"request":{"method":"GET","uri":"/","host":"h","remote_ip":"192.0.2.1"},`+
		`"status":200}`+"\n")

	if got := read(t, logReader); got != (Result{Counted: 1, NotAccess: 2}) || hits(t, db) != 1 {
		t.Errorf("third read = %+v, %d hits; want 1 counted, 2 not an access and 1 hit", got, hits(t, db))
	}

	if warnings := strings.Count(logged.String(), noAccessWarning(path)); warnings != 1 {
		t.Errorf("%d warnings of no access line, want 1:\n%s", warnings, logged.String())
	}
}

// A line in the year 10000 of the store's zone is unreadable: its nine-digit day key would break Hosts for the whole
// store.
func TestYear10000(t *testing.T) {
	db := openZone(t, "Pacific/Kiritimati")
	path := filepath.Join(t.TempDir(), "access.log")
	end := base.AddDate(8000, 0, 0).Add(-14 * time.Hour) // the first instant of the year 10000 in the store's zone
	writeLog(t, path, ncsa("192.0.2.1", "GET", "/", end.Add(-time.Second))+"\n"+ncsa("192.0.2.1", "GET", "/", end)+"\n")

	options := DefaultOptions()
	options.Now = func() time.Time { return end }

	if got := read(t, newReader(t, db, path, logparse.ParseNCSA, options)); got != (Result{Counted: 1, BadDate: 1}) {
		t.Errorf("Read = %+v, want 1 counted and 1 badly dated", got)
	}

	if _, err := db.Hosts(); err != nil {
		t.Errorf("Hosts: %v", err)
	}
}

// Once the path has a state, a read skips unreadable lines with none readable and goes on after them, and so does the
// read of a new log in its place.
func TestSkipUnreadable(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 1))
	r := reader(t, db, path)
	read(t, r)

	for _, tc := range []struct {
		name string
		log  func()
		want Result
	}{
		{"lines appended", func() { appendLog(t, path, strings.Repeat("garbage\n", 100)) }, Result{Malformed: 100}},
		{"no new line", func() {}, Result{}},
		{"a new log", func() { writeLog(t, path, "junk\n") }, Result{Malformed: 1}},
		{"no new line in it", func() {}, Result{}},
	} {
		tc.log()

		if got := read(t, r); got != tc.want {
			t.Errorf("%s: Read = %+v, want %+v", tc.name, got, tc.want)
		}
	}

	if got := hits(t, db); got != 1 {
		t.Errorf("hits = %d, want 1", got)
	}
}

// A context that ends after its first n checks.
type countdown struct {
	context.Context

	n int
}

func (c *countdown) Err() error {
	if c.n--; c.n < 0 {
		return context.Canceled
	}

	return nil
}

// A read whose context ends stops before its next line and writes nothing, though its Result counts the lines it read.
func TestReadStopped(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 3))
	r := reader(t, db, path)

	for _, tc := range []struct {
		checks int
		want   Result
	}{
		{0, Result{}},
		{2, Result{Counted: 2}},
	} {
		res, err := r.Read(&countdown{Context: t.Context(), n: tc.checks})
		if res != tc.want || !errors.Is(err, context.Canceled) {
			t.Errorf("Read stopped after %d checks = %+v, %v; want %+v, context.Canceled", tc.checks, res, err, tc.want)
		}
	}

	if _, ok, err := db.State(path); ok || err != nil || hits(t, db) != 0 {
		t.Errorf("the stopped reads wrote: a state %v, %v, %d hits", ok, err, hits(t, db))
	}

	if got := read(t, r); got != (Result{Counted: 3}) {
		t.Errorf("next Read = %+v, want 3 counted", got)
	}
}

// A read after a rotation by rename takes what the old file gained, then the new log from its start, and goes on in the
// new one; what the old file gains after that is lost.
func TestRotateRename(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 2))
	logReader := reader(t, db, path)
	read(t, logReader)
	appendLog(t, path, gets(2, 1))
	rename(t, path, path+".1")
	writeLog(t, path, gets(3, 2))

	if got := read(t, logReader); got != (Result{Counted: 3}) || hits(t, db) != 5 {
		t.Errorf("Read after the rotation = %+v, %d hits; want 3 counted, 5 hits", got, hits(t, db))
	}

	appendLog(t, path+".1", gets(5, 1))
	appendLog(t, path, gets(6, 1))

	if got := read(t, logReader); got != (Result{Counted: 1}) || hits(t, db) != 6 {
		t.Errorf("next Read = %+v, %d hits; want 1 counted, 6 hits", got, hits(t, db))
	}
}

// While the path names no file, a read fails and keeps the old one; so does a read stopped in the new log. The next
// read takes what the old file gained, then the new log.
func TestRotateFailed(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 1))
	logReader := reader(t, db, path)
	read(t, logReader)
	appendLog(t, path, gets(1, 1))
	rename(t, path, path+".1")

	if _, err := logReader.Read(t.Context()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Read with no log at the path: %v, want os.ErrNotExist", err)
	}

	writeLog(t, path, gets(2, 1))

	// The checks before the old file's line, its end and the new log's line.
	result, err := logReader.Read(&countdown{Context: t.Context(), n: 3})
	if result != (Result{Counted: 2}) || !errors.Is(err, context.Canceled) {
		t.Errorf("Read stopped in the new log = %+v, %v; want 2 counted, context.Canceled", result, err)
	}

	if got := read(t, logReader); got != (Result{Counted: 2}) || hits(t, db) != 3 {
		t.Errorf("next Read = %+v, %d hits; want 2 counted, 3 hits", got, hits(t, db))
	}
}

// While the path names no file, a read takes what a deleted log gained and releases it. The next read fails; once a new
// log is there, a read takes it from its start.
func TestDeleted(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 1))
	logReader := reader(t, db, path)
	read(t, logReader)
	appendLog(t, path, gets(1, 1))

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}

	if count := opened(t, path+" (deleted)"); count != 1 {
		t.Errorf("the deleted log is open %d times before the read, want 1", count)
	}

	if got := read(t, logReader); got != (Result{Counted: 1}) || hits(t, db) != 2 {
		t.Errorf("Read of the deleted log = %+v, %d hits; want 1 counted, 2 hits", got, hits(t, db))
	}

	if count := opened(t, path+" (deleted)"); count != 0 {
		t.Errorf("the deleted log is open %d times after the read, want 0", count)
	}

	if _, err := logReader.Read(t.Context()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("next Read: %v, want os.ErrNotExist", err)
	}

	writeLog(t, path, gets(2, 1))

	if got := read(t, logReader); got != (Result{Counted: 1}) || hits(t, db) != 3 {
		t.Errorf("Read of a new log = %+v, %d hits; want 1 counted, 3 hits", got, hits(t, db))
	}
}

// A reader keeps its log open between reads, and Close releases it. Close before a read and a second Close do nothing,
// and a read after Close opens the log again.
func TestClose(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 1))
	logReader := reader(t, db, path)

	if err := logReader.Close(); err != nil {
		t.Errorf("Close before a read: %v", err)
	}

	read(t, logReader)

	if count := opened(t, path); count != 1 {
		t.Errorf("the log is open %d times after a read, want 1", count)
	}

	for i := range 2 {
		if err := logReader.Close(); err != nil {
			t.Errorf("Close %d: %v", i+1, err)
		}
	}

	if count := opened(t, path); count != 0 {
		t.Errorf("the log is open %d times after Close, want 0", count)
	}

	appendLog(t, path, gets(1, 1))

	if got := read(t, logReader); got != (Result{Counted: 1}) {
		t.Errorf("Read after Close = %+v, want 1 counted", got)
	}
}

// Renames the file at from to to.
func rename(t *testing.T, from, to string) {
	t.Helper()

	if err := os.Rename(from, to); err != nil {
		t.Fatalf("rename: %v", err)
	}
}

// Returns how many of the process's open files are the one at path, as Linux lists them.
func opened(t *testing.T, path string) int {
	t.Helper()

	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("list open files: %v", err)
	}

	count := 0

	for _, entry := range entries {
		if target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name())); err == nil && target == path {
			count++
		}
	}

	return count
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

		if _, err := reader(t, db, path).Read(t.Context()); err == nil {
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

	if _, err := reader(t, db, path).Read(t.Context()); err == nil {
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

		if _, err := reader(t, db, dir).Read(t.Context()); err == nil {
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

	options := DefaultOptions()
	options.Count.ValidCodes = []int{404}
	options.DefaultHost = "h"
	options.Now = func() time.Time { return base }

	logReader := newReader(t, db, path, logparse.ParseNCSA, options)

	read(t, logReader)

	if got := hits(t, db); got != 0 {
		t.Errorf("hits of correct requests = %d, want 0", got)
	}

	totals, err := db.Totals("h", "2000", kvstore.Filter{Status: kvstore.AllStatuses})
	if err != nil || totals.Hits != 1 {
		t.Errorf("hits of every status = %d, %v; want 1", totals.Hits, err)
	}
}

// With NoUserAgent, a client is a human of kind unknown, whether its line names a browser or none.
func TestNoUserAgent(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	browser := ncsa("10.0.0.1", "GET", "/", base)
	noClient := strings.Replace(ncsa("10.0.0.2", "GET", "/", base), `"Mozilla/5.0 (X11; Linux x86_64)"`, `"-"`, 1)
	writeLog(t, path, browser+"\n"+noClient+"\n")

	options := DefaultOptions()
	options.DefaultHost = "h"
	options.NoUserAgent = true
	options.Now = func() time.Time { return base }

	read(t, newReader(t, db, path, logparse.ParseNCSA, options))

	kinds, err := db.Dim("h", "c", "2000", kvstore.Filter{}) // c: the client kind
	if err != nil {
		t.Fatalf("Dim: %v", err)
	}

	if len(kinds) != 1 || kinds[uaclass.Unknown].Hits != 2 {
		t.Errorf("human hits per client kind = %v, want 2 of %s", kinds, uaclass.Unknown)
	}
}

// Without a clock, a read measures the 24 hours a line may be ahead from the time it runs.
func TestClock(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	now := time.Now()
	writeLog(t, path, ncsa("10.0.0.1", "GET", "/", now)+"\n"+ncsa("10.0.0.2", "GET", "/", now.Add(2*ahead))+"\n")

	logReader := newReader(t, db, path, logparse.ParseNCSA, DefaultOptions())

	if got := read(t, logReader); got != (Result{Counted: 1, BadDate: 1}) {
		t.Errorf("Read = %+v, want 1 counted and 1 dated ahead", got)
	}
}
