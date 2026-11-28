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
	"compress/gzip"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/javierbeaumont/kirika/internal/kvstore"
	"github.com/javierbeaumont/kirika/internal/logparse"
)

// Writes text to the file name, gzipped.
func writeGzip(t *testing.T, name, text string) {
	t.Helper()

	var zipped bytes.Buffer

	writer := gzip.NewWriter(&zipped)
	if _, err := writer.Write([]byte(text)); err != nil {
		t.Fatalf("gzip: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("gzip: %v", err)
	}

	writeLog(t, name, zipped.String())
}

// Sets the modification time of the file name to base plus hours.
func touch(t *testing.T, name string, hours int) {
	t.Helper()

	at := base.Add(time.Duration(hours) * time.Hour)
	if err := os.Chtimes(name, at, at); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
}

// Returns a reader as reader does, but logging to logged at debug level.
func debugReader(t *testing.T, db *kvstore.DB, path string, logged *bytes.Buffer) *Reader {
	t.Helper()

	options := DefaultOptions()
	options.DefaultHost = "h"
	options.Log = slog.New(slog.NewTextHandler(logged, &slog.HandlerOptions{Level: slog.LevelDebug}))
	options.Now = func() time.Time { return base }

	return newReader(t, db, path, logparse.ParseNCSA, options)
}

// Reads the log at path into db with a first reader, which then stops.
func readOnce(t *testing.T, db *kvstore.DB, path string) {
	t.Helper()

	first := reader(t, db, path)
	read(t, first)

	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// A new reader whose log still holds the last line read takes nothing and looks in no rotated file, so it does not
// warn.
func TestRestartSameLog(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 2))
	readOnce(t, db, path)

	var logged bytes.Buffer

	logReader := debugReader(t, db, path, &logged)

	for range 2 {
		if got := read(t, logReader); got != (Result{}) || hits(t, db) != 2 {
			t.Errorf("Read of a new reader = %+v, %d hits; want nothing, 2 hits", got, hits(t, db))
		}
	}

	if strings.Contains(logged.String(), "level=WARN") {
		t.Errorf("warned:\n%s", logged.String())
	}
}

// With nothing gained, a new reader whose state of no line read names a line a rotated file still holds writes nothing
// to the store.
func TestRestartWritesNothing(t *testing.T) {
	dir := t.TempDir()
	store, path := filepath.Join(dir, "kirika.db"), filepath.Join(dir, "access.log")
	db := openAt(t, store, "UTC")
	writeLog(t, path, gets(0, 1))
	readOnce(t, db, path)
	rename(t, path, path+".1")
	writeLog(t, path, "")
	readOnce(t, db, path)

	before, err := os.ReadFile(store)
	if err != nil {
		t.Fatalf("read the store: %v", err)
	}

	readOnce(t, db, path)

	if after, err := os.ReadFile(store); err != nil || !bytes.Equal(before, after) {
		t.Errorf("a read with nothing gained changed the store's file, or reading it failed: %v", err)
	}
}

// A new reader whose log was rotated while none ran takes the rest of the rotated file first, then the new log; its
// reports of a rotated file's lines name that file and give the line's number in it, and those of the new log's name no
// file.
func TestRestartAfterRotation(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	trace := ncsa("192.0.2.1", "TRACE", "/", base) + "\n"

	writeLog(t, path, gets(0, 1))
	readOnce(t, db, path)
	appendLog(t, path, gets(1, 2)+trace)
	rename(t, path, path+".1")
	writeLog(t, path, gets(3, 1)+trace)

	var logged bytes.Buffer

	if got := read(t, debugReader(t, db, path, &logged)); got != (Result{Counted: 3, Dropped: 2}) || hits(t, db) != 4 {
		t.Errorf("Read = %+v, %d hits; want 3 counted, 2 dropped, 4 hits", got, hits(t, db))
	}

	var reports []string

	for report := range strings.Lines(logged.String()) {
		if strings.Contains(report, "line dropped") {
			reports = append(reports, report)
		}
	}

	if len(reports) != 2 || !strings.Contains(reports[0], "line=4 ") ||
		!strings.Contains(reports[0], "file="+path+".1") || !strings.Contains(reports[1], "line=2 ") ||
		strings.Contains(reports[1], "file=") {
		t.Errorf("reports of the dropped lines: %q; want line 4 of %s.1, then line 2 of no rotated file", reports,
			path)
	}
}

// After several rotations, a new reader takes the rest of the rotated file the last read stopped in, then each newer
// one whole, oldest first, compressed or not, then the new log.
func TestRestartAfterRotations(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 1))
	readOnce(t, db, path)
	writeGzip(t, path+".3.gz", gets(0, 2))
	writeGzip(t, path+".2.gz", gets(2, 2))
	writeLog(t, path+".1", gets(4, 1))
	writeLog(t, path, gets(5, 1))
	touch(t, path+".3.gz", 1)
	touch(t, path+".2.gz", 2)
	touch(t, path+".1", 3)

	if got := read(t, reader(t, db, path)); got != (Result{Counted: 5}) || hits(t, db) != 6 {
		t.Errorf("Read = %+v, %d hits; want 5 counted, 6 hits", got, hits(t, db))
	}
}

// When no rotated file holds the last line read, a read warns and records the new log with no line read; the next reads
// neither look for that line again nor warn.
func TestRotatedNotFound(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 1))
	readOnce(t, db, path)
	writeLog(t, path, strings.TrimSuffix(gets(1, 1), "\n"))

	var logged bytes.Buffer

	logReader := debugReader(t, db, path, &logged)

	for _, want := range []Result{{}, {Counted: 1}, {Counted: 1}} {
		if got := read(t, logReader); got != want {
			t.Errorf("Read = %+v, want %+v", got, want)
		}

		appendLog(t, path, "\n"+strings.TrimSuffix(gets(2, 1), "\n"))
	}

	warning := `level=WARN msg="the last line read is in no rotated file`
	if warnings := strings.Count(logged.String(), warning); warnings != 1 {
		t.Errorf("%d warnings of no rotated file, want 1:\n%s", warnings, logged.String())
	}
}

// A new reader whose state of no line read names a line no rotated file holds any longer takes the log from its start
// and does not warn: the log before may be gone with nothing lost.
func TestRotatedNoLineNotFound(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 1))
	readOnce(t, db, path)
	rename(t, path, path+".1")
	writeLog(t, path, "")
	readOnce(t, db, path)

	if err := os.Remove(path + ".1"); err != nil {
		t.Fatalf("remove: %v", err)
	}

	appendLog(t, path, gets(1, 1))

	var logged bytes.Buffer

	if got := read(t, debugReader(t, db, path, &logged)); got != (Result{Counted: 1}) || hits(t, db) != 2 {
		t.Errorf("Read = %+v, %d hits; want 1 counted, 2 hits", got, hits(t, db))
	}

	if strings.Contains(logged.String(), "level=WARN") {
		t.Errorf("warned:\n%s", logged.String())
	}
}

// A read that takes what a deleted log gained records the state of no line read, so the read of the next log does not
// warn.
func TestRotatedAfterDeleted(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 1))

	var logged bytes.Buffer

	logReader := debugReader(t, db, path, &logged)
	read(t, logReader)
	appendLog(t, path, gets(1, 1))

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}

	read(t, logReader)
	writeLog(t, path, gets(2, 1))

	if got := read(t, logReader); got != (Result{Counted: 1}) || hits(t, db) != 3 {
		t.Errorf("Read of the new log = %+v, %d hits; want 1 counted, 3 hits", got, hits(t, db))
	}

	if strings.Contains(logged.String(), "level=WARN") {
		t.Errorf("warned:\n%s", logged.String())
	}
}

// A read that lets a deleted log go records the state of no line read with that log's last line read, in that read or
// an earlier one. A new reader finds that line in the compressed copy a rotation left of the log, and takes each log
// written since.
func TestRestartAfterDeleted(t *testing.T) {
	for _, gained := range []int{0, 1} {
		db := openStore(t)
		path := filepath.Join(t.TempDir(), "access.log")
		writeLog(t, path, gets(0, 1))
		logReader := reader(t, db, path)
		read(t, logReader)
		appendLog(t, path, gets(1, gained))
		writeGzip(t, path+".1.gz", gets(0, 1+gained))

		if err := os.Remove(path); err != nil {
			t.Fatalf("remove: %v", err)
		}

		read(t, logReader)

		want := noLineState(t, 1+gained)
		if state, _, err := db.State(path); state != want || err != nil {
			t.Errorf("%d gained: state after the deleted log = %+v, %v; want %+v", gained, state, err, want)
		}

		if err := logReader.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		rename(t, path+".1.gz", path+".2.gz")
		writeLog(t, path+".1", gets(2, 1))
		writeLog(t, path, gets(3, 1))

		if got := read(t, reader(t, db, path)); got != (Result{Counted: 2}) || hits(t, db) != int64(3+gained) {
			t.Errorf("%d gained: Read of a new reader = %+v, %d hits; want 2 counted, %d hits", gained, got,
				hits(t, db), 3+gained)
		}
	}
}

// Once no rotated file holds the line a state of no line read names, the state names none, and a new reader looks in no
// rotated file.
func TestRotatedNothingBefore(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 1))
	readOnce(t, db, path)
	rename(t, path, path+".1")
	writeLog(t, path, "")
	readOnce(t, db, path)

	if err := os.Remove(path + ".1"); err != nil {
		t.Fatalf("remove: %v", err)
	}

	readOnce(t, db, path)

	if state, ok, err := db.State(path); state != noLineBefore || !ok || err != nil {
		t.Errorf("state = %+v, %v, %v; want %+v", state, ok, err, noLineBefore)
	}

	if err := os.Symlink(path+".1", path+".1"); err != nil { // a rotated file whose opening fails with a warning
		t.Fatalf("symlink: %v", err)
	}

	var logged bytes.Buffer

	if got := read(t, debugReader(t, db, path, &logged)); got != (Result{}) || strings.Contains(logged.String(),
		"level=WARN") {
		t.Errorf("Read = %+v, logged:\n%s\nwant nothing", got, logged.String())
	}
}

// A reader that keeps its log open does not look in the rotated files: of a log copied aside and truncated in place, it
// takes only the lines the log holds now.
func TestCopyTruncateKept(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 1))
	logReader := reader(t, db, path)
	read(t, logReader)
	appendLog(t, path, gets(1, 2))
	writeLog(t, path+".1", gets(0, 3))
	writeLog(t, path, gets(3, 1))
	touch(t, path+".1", 1)

	if got := read(t, logReader); got != (Result{Counted: 1}) || hits(t, db) != 2 {
		t.Errorf("Read = %+v, %d hits; want 1 counted, 2 hits", got, hits(t, db))
	}
}

// A rotated file compressed in another format than gzip, or a gzip one that cannot be read, is skipped with one
// warning; one cut short is read up to there.
func TestRotatedUnreadable(t *testing.T) {
	db := openStore(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	writeLog(t, path, gets(0, 1))
	readOnce(t, db, path)
	appendLog(t, path, gets(1, 1))
	rename(t, path, path+".6")
	writeLog(t, path+".5.bz2", "BZh91AY&SY"+gets(2, 1))
	writeLog(t, path+".4.xz", "\xfd7zXZ\x00"+gets(2, 1))
	writeLog(t, path+".3.zst", "\x28\xb5\x2f\xfd"+gets(2, 1))
	writeLog(t, path+".2.gz", "\x1f\x8bnot gzip\n")
	writeGzip(t, filepath.Join(dir, "whole.gz"), gets(3, 2))

	whole, err := os.ReadFile(filepath.Join(dir, "whole.gz"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	writeLog(t, path+".1.gz", string(whole[:len(whole)-8])) // with no trailer
	writeLog(t, path, gets(5, 1))

	for hours, suffix := range []string{".6", ".5.bz2", ".4.xz", ".3.zst", ".2.gz", ".1.gz"} {
		touch(t, path+suffix, hours)
	}

	var logged bytes.Buffer

	if got := read(t, debugReader(t, db, path, &logged)); got != (Result{Counted: 4}) || hits(t, db) != 5 {
		t.Errorf("Read = %+v, %d hits; want 4 counted, 5 hits", got, hits(t, db))
	}

	for warning, want := range map[string]int{
		"compressed in a format a read cannot take": 3,
		"unreadable from here on":                   2,
	} {
		if got := strings.Count(logged.String(), warning); got != want {
			t.Errorf("%d warnings say %q, want %d:\n%s", got, warning, want, logged.String())
		}
	}
}

// A gzip rotated file cut short before the line a read looks for gives no line and one warning, and the read goes on.
func TestRotatedCutBeforeLine(t *testing.T) {
	db := openStore(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	writeLog(t, path, gets(0, 2))
	readOnce(t, db, path)
	appendLog(t, path, gets(2, 1))
	rename(t, path, path+".2")
	writeGzip(t, filepath.Join(dir, "whole.gz"), gets(3, 3))

	whole, err := os.ReadFile(filepath.Join(dir, "whole.gz"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	writeLog(t, path+".1.gz", string(whole[:20]))
	writeLog(t, path, gets(6, 1))
	touch(t, path+".2", 1)
	touch(t, path+".1.gz", 2)

	var logged bytes.Buffer

	if got := read(t, debugReader(t, db, path, &logged)); got != (Result{Counted: 2}) || hits(t, db) != 4 {
		t.Errorf("Read = %+v, %d hits; want 2 counted, 4 hits", got, hits(t, db))
	}

	if warnings := strings.Count(logged.String(), "unreadable from here on"); warnings != 1 {
		t.Errorf("%d warnings of an unreadable file, want 1:\n%s", warnings, logged.String())
	}
}

// Two of logrotate's numbered rotated files order by their number, whatever their times: a copy compressed after the
// next rotation is not newer than the file that rotation made.
func TestRotatedNumberFirst(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 1))
	readOnce(t, db, path)
	appendLog(t, path, gets(1, 1))
	rename(t, path, path+".1")
	writeGzip(t, path+".2.gz", gets(5, 3))
	writeLog(t, path, gets(9, 1))
	touch(t, path+".1", 24)
	touch(t, path+".2.gz", 25)

	if got := read(t, reader(t, db, path)); got != (Result{Counted: 2}) || hits(t, db) != 3 {
		t.Errorf("Read = %+v, %d hits; want 2 counted, 3 hits", got, hits(t, db))
	}
}

// A gzip rotated file cut short before the offset a read looks for does not hold its line, and is read whole after, up
// to the cut, as a newer one.
func TestRotatedCutNewer(t *testing.T) {
	db := openStore(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	writeLog(t, path, gets(0, 6))
	readOnce(t, db, path)
	appendLog(t, path, gets(6, 1))
	rename(t, path, path+".2")
	writeGzip(t, filepath.Join(dir, "whole.gz"), gets(7, 2))

	whole, err := os.ReadFile(filepath.Join(dir, "whole.gz"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	writeLog(t, path+".1.gz", string(whole[:len(whole)-8])) // with no trailer
	writeLog(t, path, gets(9, 1))
	touch(t, path+".2", 1)
	touch(t, path+".1.gz", 2)

	if got := read(t, reader(t, db, path)); got != (Result{Counted: 4}) || hits(t, db) != 10 {
		t.Errorf("Read = %+v, %d hits; want 4 counted, 10 hits", got, hits(t, db))
	}
}

// A move to a log with no line yet keeps the last line read before, even when the read took no line of the log before:
// a new reader finds that log, then takes the one moved to once it is rotated in its turn, whether the reader that
// moved kept its log open or not.
func TestRotatedNothingGained(t *testing.T) {
	for _, kept := range []bool{false, true} {
		db := openStore(t)
		path := filepath.Join(t.TempDir(), "access.log")
		writeLog(t, path, gets(0, 1))

		first := reader(t, db, path)
		read(t, first)

		if !kept {
			if err := first.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
		}

		rename(t, path, path+".1")
		writeLog(t, path, "")
		read(t, first)

		if err := first.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		appendLog(t, path, gets(1, 2))
		rename(t, path+".1", path+".2")
		rename(t, path, path+".1")
		writeLog(t, path, gets(3, 1))
		touch(t, path+".2", 1)
		touch(t, path+".1", 2)

		if got := read(t, reader(t, db, path)); got != (Result{Counted: 3}) || hits(t, db) != 4 {
			t.Errorf("kept %v: Read = %+v, %d hits; want 3 counted, 4 hits", kept, got, hits(t, db))
		}
	}
}

// Of two daily runs, the first, right after a rotation, takes the rest of the rotated log and moves to an empty new
// one; the next finds the rotated log again after the next rotation and takes the one moved to whole.
func TestRotatedAfterEmptyLog(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 1))
	readOnce(t, db, path)
	appendLog(t, path, gets(1, 1))
	rename(t, path, path+".1")
	writeLog(t, path, "")
	readOnce(t, db, path)
	appendLog(t, path, gets(2, 2))
	rename(t, path+".1", path+".2")
	rename(t, path, path+".1")
	writeLog(t, path, gets(4, 1))
	touch(t, path+".2", 1)
	touch(t, path+".1", 2)

	if got := read(t, reader(t, db, path)); got != (Result{Counted: 3}) || hits(t, db) != 5 {
		t.Errorf("Read = %+v, %d hits; want 3 counted, 5 hits", got, hits(t, db))
	}
}

// Rotated files newer than the one a read stopped in are read oldest first, so a read stopped in one of them goes on in
// the next.
func TestRotatedOrder(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 1))
	readOnce(t, db, path)
	rename(t, path, path+".3")
	writeLog(t, path+".2", gets(1, 1))
	writeLog(t, path+".1", gets(2, 1))
	writeLog(t, path, gets(3, 1))

	for hours, name := range []string{path + ".3", path + ".2", path + ".1"} {
		touch(t, name, hours)
	}

	logReader := reader(t, db, path)
	logReader.chunk = 1

	// The checks before each of the three rotated files, the oldest one's end, and the next one's line and end.
	if _, err := logReader.Read(&countdown{Context: t.Context(), n: 6}); !errors.Is(err, context.Canceled) ||
		hits(t, db) != 2 {
		t.Errorf("stopped Read: %v, %d hits; want context.Canceled, 2 hits", err, hits(t, db))
	}

	if got := read(t, logReader); got != (Result{Counted: 2}) || hits(t, db) != 4 {
		t.Errorf("next Read = %+v, %d hits; want 2 counted, 4 hits", got, hits(t, db))
	}
}

// Another log beside the rotated one, newer than its rotated files, is no rotated file of it.
func TestRotatedOtherLog(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 1))
	readOnce(t, db, path)
	appendLog(t, path, gets(1, 1))
	rename(t, path, path+".1")
	writeLog(t, filepath.Join(filepath.Dir(path), "access-api.log"), gets(2, 2))
	writeLog(t, path, gets(4, 1))
	touch(t, path+".1", 1)

	if got := read(t, reader(t, db, path)); got != (Result{Counted: 2}) || hits(t, db) != 3 {
		t.Errorf("Read = %+v, %d hits; want 2 counted, 3 hits", got, hits(t, db))
	}
}

// The globs of Options.Rotated replace the default ones, a relative one from the log's directory, which may hold
// pattern characters; a file two of them match is read once, and the log one of them matches is no rotated file.
func TestRotatedOption(t *testing.T) {
	db := openStore(t)
	dir := filepath.Join(t.TempDir(), "[logs]")

	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	path := filepath.Join(dir, "access.log")
	writeLog(t, path, gets(0, 1))
	readOnce(t, db, path)
	appendLog(t, path, gets(1, 1))

	if err := os.Mkdir(filepath.Join(dir, "old"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	rename(t, path, filepath.Join(dir, "old", "access.log.2"))
	writeLog(t, filepath.Join(dir, "old", "access.log.1"), gets(2, 1))
	writeLog(t, path, gets(3, 1))
	touch(t, filepath.Join(dir, "old", "access.log.2"), 1)
	touch(t, filepath.Join(dir, "old", "access.log.1"), 2)

	options := DefaultOptions()
	options.DefaultHost = "h"
	options.Now = func() time.Time { return base }
	options.Rotated = []string{"old/access.log.*", "old/access.log.[0-9]", "access.log*"}

	if got := read(t, newReader(t, db, path, logparse.ParseNCSA, options)); got != (Result{Counted: 3}) ||
		hits(t, db) != 4 {
		t.Errorf("Read = %+v, %d hits; want 3 counted, 4 hits", got, hits(t, db))
	}
}

// A rotated file shorter than the last line read's offset does not hold it.
func TestRotatedShort(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 2))
	readOnce(t, db, path)
	appendLog(t, path, gets(2, 1))
	rename(t, path, path+".2")
	writeGzip(t, path+".1.gz", "short\n")
	writeLog(t, path, gets(3, 1))
	touch(t, path+".2", 1)
	touch(t, path+".1.gz", 2)

	if got := read(t, reader(t, db, path)); got != (Result{Counted: 2, Malformed: 1}) || hits(t, db) != 4 {
		t.Errorf("Read = %+v, %d hits; want 2 counted, 1 malformed, 4 hits", got, hits(t, db))
	}
}

// A rotated file under two names, or beside its gzip copy, is read once and closed after, and a directory or a dangling
// link with a rotated file's name not at all; of two files of one time, logrotate's higher number is the older, .10
// older than .9 too. A rotated file whose first line starts as a bzip2 one is read.
func TestRotatedOnce(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 1))
	readOnce(t, db, path)
	appendLog(t, path, gets(1, 1))
	rename(t, path, path+".10")
	writeLog(t, path+".9", gets(2, 1))
	writeGzip(t, path+".9.gz", gets(2, 1))

	if err := os.Link(path+".9", path+".9-link"); err != nil {
		t.Fatalf("link: %v", err)
	}

	if err := os.Mkdir(path+".5", 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if err := os.Symlink(path+".gone", path+".7"); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	writeLog(t, path+".1", ncsa("BZhang-pc.lan", "GET", "/", base)+"\n")
	writeLog(t, path, gets(4, 1))

	for _, suffix := range []string{".10", ".9", ".9.gz", ".1"} {
		touch(t, path+suffix, 1)
	}

	var logged bytes.Buffer

	if got := read(t, debugReader(t, db, path, &logged)); got != (Result{Counted: 4}) || hits(t, db) != 5 {
		t.Errorf("Read = %+v, %d hits; want 4 counted, 5 hits", got, hits(t, db))
	}

	if strings.Contains(logged.String(), "level=WARN") {
		t.Errorf("warned:\n%s", logged.String())
	}

	for _, suffix := range []string{".10", ".9", ".9.gz", ".9-link", ".5", ".1"} {
		if count := opened(t, path+suffix); count != 0 {
			t.Errorf("%s is open %d times after the read, want 0", path+suffix, count)
		}
	}
}

// A rotated file that cannot be opened, as a link to itself, is skipped with a warning.
func TestRotatedNoAccess(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 1))
	readOnce(t, db, path)
	appendLog(t, path, gets(1, 1))
	rename(t, path, path+".2")
	writeLog(t, path, gets(2, 1))

	if err := os.Symlink(path+".1", path+".1"); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	var logged bytes.Buffer

	if got := read(t, debugReader(t, db, path, &logged)); got != (Result{Counted: 2}) || hits(t, db) != 3 {
		t.Errorf("Read = %+v, %d hits; want 2 counted, 3 hits", got, hits(t, db))
	}

	if warnings := strings.Count(logged.String(), "cannot be opened"); warnings != 1 {
		t.Errorf("%d warnings of a file that cannot be opened, want 1:\n%s", warnings, logged.String())
	}
}

// A read stopped in a rotated file keeps the chunks it flushed there, and the next read finds that file again by its
// line and goes on after it.
func TestRotatedStopped(t *testing.T) {
	db := openStore(t)
	path := filepath.Join(t.TempDir(), "access.log")
	writeLog(t, path, gets(0, 1))
	readOnce(t, db, path)
	appendLog(t, path, gets(1, 2))
	rename(t, path, path+".1")
	writeLog(t, path, gets(3, 1))

	logReader := reader(t, db, path)
	logReader.chunk = 1

	// The checks before the rotated file and before its first line a read takes.
	if _, err := logReader.Read(&countdown{Context: t.Context(), n: 2}); !errors.Is(err, context.Canceled) ||
		hits(t, db) != 2 {
		t.Errorf("stopped Read: %v, %d hits; want context.Canceled, 2 hits", err, hits(t, db))
	}

	if got := read(t, logReader); got != (Result{Counted: 2}) || hits(t, db) != 4 {
		t.Errorf("next Read = %+v, %d hits; want 2 counted, 4 hits", got, hits(t, db))
	}
}
