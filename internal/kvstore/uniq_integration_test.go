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
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/javierbeaumont/kirika/internal/logparse"
	bolt "go.etcd.io/bbolt"
)

// Reports whether got is within 5% of want, about three times the sketch's standard error.
func near(got uint64, want int) bool {
	return math.Abs(float64(got)-float64(want)) <= 0.05*float64(want)
}

func unique(t *testing.T, db *DB, host, period string, f Filter) uint64 {
	t.Helper()

	n, err := db.Unique(period, f, host)
	if err != nil {
		t.Fatalf("Unique(%q, %+v, %q): %v", period, f, host, err)
	}

	return n
}

// A client counts in the class of each of its pages, and once under a filter that takes several of them. The kind of a
// filter changes nothing.
func TestUniqueFilters(t *testing.T) {
	db := openStore(t)

	bot := page("h", "/", 200, 1, base)
	bot.UserAgent = botUA

	flush(t, db,
		from(ip(0), page("h", "/", 200, 1, base)),
		from(ip(0), page("h", "/missing", 404, 1, base)),
		from(ip(1), page("h", "/missing", 404, 1, base)),
		from(ip(2), page("h", "/moved", 301, 1, base)),
		from(ip(3), bot),
	)

	for _, tc := range []struct {
		f    Filter
		want uint64
	}{
		{Filter{}, 1},
		{Filter{Kind: FileKind}, 1},
		{Filter{Status: Errors}, 2},
		{Filter{Status: AllStatuses}, 3},
		{Filter{Audience: Bots}, 1},
		{Filter{Audience: AllAudiences, Status: AllStatuses}, 4},
	} {
		if got := unique(t, db, "h", "2000-01", tc.f); got != tc.want {
			t.Errorf("Unique with %+v = %d, want %d", tc.f, got, tc.want)
		}
	}
}

// Flushes merge into the stored sketch, and a year merges months that share clients.
func TestUniqueMerges(t *testing.T) {
	db := openStore(t)
	next := base.AddDate(0, 1, 0)

	flush(t, db, visits("h", 0, 600, base)...)
	flush(t, db, visits("h", 400, 1000, next)...)
	flush(t, db, visits("h", 300, 900, base)...)

	for period, want := range map[string]int{"2000-01": 900, next.Format("2006-01"): 600, "2000": 1000} {
		if got := unique(t, db, "h", period, Filter{}); !near(got, want) {
			t.Errorf("Unique(%q) = %d, want about %d", period, got, want)
		}
	}
}

// A client counts once across hosts, and a host named twice counts once. With no host, the count is 0.
func TestUniqueHosts(t *testing.T) {
	db := openStore(t)
	flush(t, db, visits("a", 0, 1000, base)...)
	flush(t, db, visits("b", 500, 1500, base.AddDate(0, 1, 0))...)

	for _, tc := range []struct {
		hosts []string
		want  int
	}{
		{nil, 0},
		{[]string{"a", "B"}, 1500},
		{[]string{"a", "A"}, 1000},
	} {
		if got, err := db.Unique("2000", Filter{}, tc.hosts...); err != nil || !near(got, tc.want) {
			t.Errorf("Unique of %q = %d, %v; want about %d", tc.hosts, got, err, tc.want)
		}
	}
}

// No client address reaches the store file.
func TestUniqueNoIP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kirika.db")

	db, err := Open(path, time.Second, "UTC")
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	evs := visits("h", 0, 5000, base)
	flush(t, db, evs...)
	closeStore(t, db)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	for _, ev := range evs {
		if bytes.Contains(data, []byte(ev.ClientIP)) {
			t.Fatalf("the store file holds the IP %s", ev.ClientIP)
		}
	}
}

// A sketch stays sparse while it holds few clients: ten take tens of bytes.
func TestSketchSparse(t *testing.T) {
	db := openStore(t)
	flush(t, db, visits("h", 0, 10, base)...)

	key := uniqKey("h", base.Format("200601"), newClass(false, groupCorrect))

	err := db.file.View(func(tx *bolt.Tx) error {
		if n := len(tx.Bucket(bktUniq).Get(key)); n == 0 || n > 100 {
			t.Errorf("the sketch of ten clients takes %d bytes, want 1 to 100", n)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("view: %v", err)
	}
}

// Returns the stored key of a year's sketches, or nil.
func storedYearKey(t *testing.T, db *DB, year string) []byte {
	t.Helper()

	var key []byte

	err := db.file.View(func(tx *bolt.Tx) error {
		key = bytes.Clone(tx.Bucket(bktKeys).Get([]byte(year)))

		return nil
	})
	if err != nil {
		t.Fatalf("view: %v", err)
	}

	return key
}

// A sketch takes each client as an HMAC-SHA256 under its year's key, and each year has its own key, in one flush too.
func TestSketchKeyed(t *testing.T) {
	db := openStore(t)
	nextYear := base.AddDate(1, 0, 0)
	flush(t, db, append(visits("h", 0, 500, base), visits("h", 0, 500, nextYear)...)...)

	key, nextKey := storedYearKey(t, db, "2000"), storedYearKey(t, db, nextYear.Format("2006"))
	if len(key) != yearKeyLen || len(nextKey) != yearKeyLen || bytes.Equal(key, nextKey) {
		t.Fatalf("year keys %x and %x, want two different ones of %d bytes", key, nextKey, yearKeyLen)
	}

	hmacUnder := func(key []byte) func(client string) []byte {
		return func(client string) []byte {
			mac := hmac.New(sha256.New, key)
			mac.Write([]byte(client))

			return mac.Sum(nil)
		}
	}

	for name, tc := range map[string]struct {
		month time.Time
		hash  func(client string) []byte
		want  int
	}{
		"own hash":                       {base, func(client string) []byte { return []byte(client) }, 1000},
		"HMAC under the key":             {base, hmacUnder(key), 500},
		"HMAC under the next year's key": {nextYear, hmacUnder(nextKey), 500},
	} {
		probe := newSketch()
		for i := range 500 {
			probe.Insert(tc.hash(ip(i)))
		}

		err := db.file.View(func(tx *bolt.Tx) error {
			stored, ok := loadSketch(tx.Bucket(bktUniq).Get(uniqKey("h", tc.month.Format("200601"), humanVisits)))
			if !ok {
				return errors.New("no stored sketch")
			}

			if err := stored.Merge(probe); err != nil {
				return err
			}

			if got := stored.Estimate(); !near(got, tc.want) {
				t.Errorf("%s: the stored sketch merged with the clients' = %d, want about %d", name, got, tc.want)
			}

			return nil
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// Flushes evs in one batch and returns how many of its pages with a client are of a closed year.
func flushClosed(t *testing.T, db *DB, evs ...logparse.Event) int {
	t.Helper()

	b := db.NewBatch(DefaultOptions())
	for _, ev := range evs {
		b.Apply(ev)
	}

	closedYearPages, err := db.Flush(b)
	if err != nil {
		t.Fatalf("flush: %v", err)
	}

	return closedYearPages
}

// A year closes when the store counts a page dated in February of the next year or later, and a page of January closes
// the years up to the one before last. A closed year's key is deleted, and so is a key with no year. A page of a closed
// year, or of an older one that never had a key, then counts in all but the unique visitors, and the flush tells how
// many of them have a client.
func TestYearCloses(t *testing.T) {
	db := openStore(t)
	nextYear := base.AddDate(1, 0, 0)
	flush(t, db, append(visits("h", 0, 100, base), visits("h", 0, 100, nextYear)...)...)
	putRaw(t, db, bktKeys, []byte("no year"), bytes.Repeat([]byte{1}, yearKeyLen))

	flush(t, db, from(ip(0), page("h", "/", 200, 1, nextYear.AddDate(1, 0, 0))))

	if storedYearKey(t, db, "2000") != nil || storedYearKey(t, db, "no year") != nil {
		t.Error("a page of January two years on left the key of the year before last or a key with no year")
	}

	if storedYearKey(t, db, nextYear.Format("2006")) == nil {
		t.Fatal("a page of January closed the year before")
	}

	flush(t, db, from(ip(0), page("h", "/", 200, 1, nextYear.AddDate(1, 1, 0))))

	if storedYearKey(t, db, nextYear.Format("2006")) != nil {
		t.Error("a page of February left the key of the year before")
	}

	before, beforeNext := unique(t, db, "h", "2000", Filter{}), unique(t, db, "h", nextYear.Format("2006"), Filter{})
	late := append(visits("h", 100, 200, base),
		from(ip(0), page("h", "/", 200, 1, base.AddDate(-1, 0, 0))),
		from(ip(500), page("h", "/", 200, 1, nextYear)))

	if got := flushClosed(t, db, late...); got != 102 {
		t.Errorf("a flush of 102 pages of closed years tells %d", got)
	}

	if got := unique(t, db, "h", "2000", Filter{}); got != before {
		t.Errorf("unique visitors of a closed year = %d after a late log, want %d", got, before)
	}

	if got := unique(t, db, "h", nextYear.Format("2006"), Filter{}); got != beforeNext {
		t.Errorf("unique visitors of the last closed year = %d after a late log, want %d", got, beforeNext)
	}

	if got := totals(t, db, "h", "2000", Filter{}).Pages; got != 200 {
		t.Errorf("pages of a closed year = %d, want 200", got)
	}

	for _, year := range []time.Time{base.AddDate(-1, 0, 0), base, nextYear} {
		if storedYearKey(t, db, year.Format("2006")) != nil {
			t.Errorf("a page of the closed year %s made a key", year.Format("2006"))
		}
	}
}

// The flush whose page closes a year still adds its own pages of that year to the unique visitors.
func TestYearClosesAfterItsBatch(t *testing.T) {
	db := openStore(t)
	february := base.AddDate(1, 1, 0)

	if got := flushClosed(t, db, append(visits("h", 0, 100, base), visits("h", 0, 1, february)...)...); got != 0 {
		t.Errorf("a flush that closes a year tells %d pages of a closed year, want 0", got)
	}

	if got := unique(t, db, "h", "2000", Filter{}); !near(got, 100) {
		t.Errorf("unique visitors = %d, want about 100", got)
	}

	if storedYearKey(t, db, "2000") != nil {
		t.Error("the closed year keeps its key")
	}
}

// A flush whose newest page is of a closed year leaves the closed years closed.
func TestClosedYearStays(t *testing.T) {
	db := openStore(t)
	flush(t, db, visits("h", 0, 10, base)...)
	flush(t, db, from(ip(0), page("h", "/", 200, 1, base.AddDate(2, 1, 0))))
	flush(t, db, from(ip(0), page("h", "/", 200, 1, base.AddDate(1, 0, 0))))

	before := unique(t, db, "h", "2000", Filter{})

	if got := flushClosed(t, db, visits("h", 100, 200, base)...); got != 100 {
		t.Errorf("a flush of 100 pages of a closed year tells %d", got)
	}

	if got := unique(t, db, "h", "2000", Filter{}); got != before {
		t.Errorf("unique visitors of a closed year = %d, want %d", got, before)
	}
}

// With no year closed, a page of the year 0 in the store's zone, an hour into the year 1 in UTC, adds its client to the
// unique visitors.
func TestYearZeroOpen(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "kirika.db"), time.Second, "America/New_York")
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	t.Cleanup(func() { closeStore(t, db) })

	yearOne := base.AddDate(-1999, 0, 0).Add(time.Hour)

	if got := flushClosed(t, db, visits("h", 0, 10, yearOne)...); got != 0 {
		t.Errorf("a flush of the year 0 tells %d pages of a closed year, want 0", got)
	}

	if got := unique(t, db, "h", "0000-12", Filter{}); got != 10 {
		t.Errorf("unique visitors of the year 0 = %d, want 10", got)
	}
}

// A flush refuses a last closed year it cannot read.
func TestClosedYearCorrupt(t *testing.T) {
	for _, stored := range []string{"", "x", "-1"} {
		db := openStore(t)
		putRaw(t, db, bktMeta, metaClosed, []byte(stored))

		b := db.NewBatch(DefaultOptions())
		b.Apply(page("h", "/", 200, 1, base))

		if _, err := db.Flush(b); !errors.Is(err, errClosedCorrupt) {
			t.Errorf("last closed year %q: err = %v, want errClosedCorrupt", stored, err)
		}
	}
}

// A stored year key of another size is replaced by a new one.
func TestYearKeyReplaced(t *testing.T) {
	db := openStore(t)
	putRaw(t, db, bktKeys, []byte("2000"), []byte{1})
	flush(t, db, visits("h", 0, 10, base)...)

	if key := storedYearKey(t, db, "2000"); len(key) != yearKeyLen {
		t.Errorf("year key %x, want %d bytes", key, yearKeyLen)
	}
}

// An unreadable stored sketch counts as empty, and the next flush replaces it.
func TestUnreadableSketch(t *testing.T) {
	dense := blob(t, hllPrecision, 20000)
	key := uniqKey("h", base.Format("200601"), newClass(false, groupCorrect))

	for name, b := range map[string][]byte{
		"not a sketch":        []byte("not a sketch"),
		"other precision":     blob(t, 14, 100),
		"cut":                 dense[:len(dense)-1],
		"trailing byte":       append(bytes.Clone(dense), 0),
		"unknown version":     append([]byte{9}, dense[1:]...),
		"unknown sparse flag": append(append([]byte(nil), dense[:3]...), append([]byte{2}, dense[4:]...)...),
		"register too high":   append(bytes.Clone(dense[:len(dense)-1]), 64),
	} {
		db := openStore(t)
		putRaw(t, db, bktUniq, key, b)

		if got := unique(t, db, "h", "2000-01", Filter{}); got != 0 {
			t.Errorf("%s: Unique = %d, want 0", name, got)
		}

		flush(t, db, visits("h", 0, 300, base)...)

		if got := unique(t, db, "h", "2000-01", Filter{}); !near(got, 300) {
			t.Errorf("%s: Unique after a flush = %d, want about 300", name, got)
		}
	}
}
