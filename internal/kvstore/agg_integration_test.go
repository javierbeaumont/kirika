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
	"math"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/javierbeaumont/kirika/internal/logparse"
	bolt "go.etcd.io/bbolt"
)

// Returns a store in a fresh directory, closed when the test ends.
func openStore(t *testing.T) *DB {
	t.Helper()

	db, err := Open(filepath.Join(t.TempDir(), "kirika.db"), time.Second, "UTC")
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	t.Cleanup(func() { closeStore(t, db) })

	return db
}

// Applies evs in one batch with the default options and flushes it.
func flush(t *testing.T, db *DB, evs ...logparse.Event) {
	t.Helper()

	b := db.NewBatch(DefaultOptions())
	for _, ev := range evs {
		b.Apply(ev)
	}

	if err := db.Flush(b); err != nil {
		t.Fatalf("flush: %v", err)
	}
}

func totals(t *testing.T, db *DB, host, period string, f Filter) Counts {
	t.Helper()

	c, err := db.Totals(host, period, f)
	if err != nil {
		t.Fatalf("Totals(%q, %q, %+v): %v", host, period, f, err)
	}

	return c
}

func dim(t *testing.T, db *DB, host, tag, period string, f Filter) map[string]Counts {
	t.Helper()

	m, err := db.Dim(host, tag, period, f)
	if err != nil {
		t.Fatalf("Dim(%q, %q, %q, %+v): %v", host, tag, period, f, err)
	}

	return m
}

func series(t *testing.T, db *DB, host, tag, period string, f Filter) []TimePoint {
	t.Helper()

	s, err := db.Series(host, tag, period, f)
	if err != nil {
		t.Fatalf("Series(%q, %q, %q, %+v): %v", host, tag, period, f, err)
	}

	return s
}

// Stores a raw value under key in a bucket.
func putRaw(t *testing.T, db *DB, bkt, key, v []byte) {
	t.Helper()

	err := db.b.Update(func(tx *bolt.Tx) error { return tx.Bucket(bkt).Put(key, v) })
	if err != nil {
		t.Fatalf("put: %v", err)
	}
}

// Returns c with v visits.
func withVisits(c Counts, v int64) Counts {
	c.Visits = v

	return c
}

// Totals, Series and Dim read what flushes stored: a host's counters over a year, a month or a day, its days or hours
// in date order, and a month's values of each dimension. An empty host reads the unknown one.
func TestReads(t *testing.T) {
	db := openStore(t)
	referred := page("a.example", "/", 200, 10, at(1, 10))
	referred.Referer = "https://r.example/"
	mobile := page("a.example", "/", 200, 10, at(1, 10))
	mobile.UserAgent = mobileUA
	flush(t, db,
		referred,
		mobile,
		page("a.example", "/logo.png", 304, 0, at(1, 11)),
		page("a.example", "/blog", 200, 20, at(2, 0)),
		page("", "/", 200, 5, at(2, 0)),
		page("a.example", "/", 200, 7, at(1, 0).AddDate(0, 1, 0)),
	)

	day := func(d int) string { return at(d, 0).Format("2006-01-02") }

	for _, tc := range []struct {
		host, period string
		want         Counts
	}{
		{"a.example", "2000", Counts{HitBandwidth: 47, Hits: 5, PageBandwidth: 47, Pages: 4}},
		{"a.example", "2000-01", Counts{HitBandwidth: 40, Hits: 4, PageBandwidth: 40, Pages: 3}},
		{"a.example", "2000-01-01", Counts{HitBandwidth: 20, Hits: 3, PageBandwidth: 20, Pages: 2}},
		{"a.example", day(3), Counts{}},
		{"unknown", "2000-01", pageCounts(1, 5)},
		{"", "2000-01", pageCounts(1, 5)},
		{"b.example", "2000", Counts{}},
	} {
		if got := totals(t, db, tc.host, tc.period, Filter{}); got != tc.want {
			t.Errorf("Totals(%q, %q) = %+v, want %+v", tc.host, tc.period, got, tc.want)
		}
	}

	wantDays := []TimePoint{
		{at(1, 0).Format("20060102"), Counts{HitBandwidth: 20, Hits: 3, PageBandwidth: 20, Pages: 2}},
		{at(2, 0).Format("20060102"), pageCounts(1, 20)},
		{at(1, 0).AddDate(0, 1, 0).Format("20060102"), pageCounts(1, 7)},
	}
	if got := series(t, db, "a.example", tagDay, "2000", Filter{}); !reflect.DeepEqual(got, wantDays) {
		t.Errorf("day series = %+v, want %+v", got, wantDays)
	}

	wantHours := []TimePoint{
		{at(1, 10).Format("2006010215"), pageCounts(2, 20)},
		{at(1, 11).Format("2006010215"), Counts{Hits: 1}},
	}
	if got := series(t, db, "a.example", tagHour, "2000-01-01", Filter{}); !reflect.DeepEqual(got, wantHours) {
		t.Errorf("hour series = %+v, want %+v", got, wantHours)
	}

	for _, tc := range []struct {
		tag  string
		want map[string]Counts
	}{
		{tagURL, map[string]Counts{"/": pageCounts(2, 20), "/logo.png": {Hits: 1}, "/blog": pageCounts(1, 20)}},
		{tagStat, map[string]Counts{"200": pageCounts(3, 40), "304": {Hits: 1}}},
		{tagRef, map[string]Counts{"https://r.example/": pageCounts(1, 10)}},
		{tagCli, map[string]Counts{
			"desktop": {HitBandwidth: 30, Hits: 3, PageBandwidth: 30, Pages: 2},
			"mobile":  pageCounts(1, 10),
		}},
	} {
		if got := dim(t, db, "a.example", tc.tag, "2000-01", Filter{}); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("Dim(%q, January) = %+v, want %+v", tc.tag, got, tc.want)
		}
	}
}

// Every read counts only what its filter picks, and leaves out a bucket or a value it picks nothing of.
func TestFilters(t *testing.T) {
	db := openStore(t)
	bot := page("h", "/missing.png", 404, 3, at(2, 0))
	bot.UserAgent = botUA
	flush(t, db, page("h", "/", 200, 10, at(1, 0)), page("h", "/logo.png", 200, 4, at(1, 0)), bot)

	bots := Filter{Audience: Bots, Status: Errors}
	all := Filter{Audience: AllAudiences, Status: AllStatuses}

	for _, tc := range []struct {
		f    Filter
		want Counts
	}{
		{Filter{}, Counts{HitBandwidth: 14, Hits: 2, PageBandwidth: 10, Pages: 1}},
		{Filter{Kind: PageKind}, pageCounts(1, 10)},
		{Filter{Kind: FileKind}, Counts{HitBandwidth: 4, Hits: 1}},
		{bots, Counts{HitBandwidth: 3, Hits: 1}},
		{all, Counts{HitBandwidth: 17, Hits: 3, PageBandwidth: 10, Pages: 1}},
	} {
		if got := totals(t, db, "h", "2000", tc.f); got != tc.want {
			t.Errorf("Totals(%+v) = %+v, want %+v", tc.f, got, tc.want)
		}
	}

	day1, day2 := at(1, 0).Format("20060102"), at(2, 0).Format("20060102")

	for _, tc := range []struct {
		f    Filter
		want []string
	}{{Filter{}, []string{day1}}, {bots, []string{day2}}, {all, []string{day1, day2}}} {
		var got []string
		for _, p := range series(t, db, "h", tagDay, "2000", tc.f) {
			got = append(got, p.At)
		}

		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("Series(%+v) days = %v, want %v", tc.f, got, tc.want)
		}
	}

	for _, tc := range []struct {
		f    Filter
		want int
	}{{Filter{}, 2}, {Filter{Kind: FileKind}, 2}, {bots, 1}, {all, 3}} {
		if got := dim(t, db, "h", tagURL, "2000", tc.f); len(got) != tc.want {
			t.Errorf("Dim(%+v) = %+v, want %d values", tc.f, got, tc.want)
		}
	}
}

// A year merges its months and a day reads its month.
func TestDimPeriods(t *testing.T) {
	db := openStore(t)
	flush(t, db,
		page("h", "/", 200, 1, at(1, 0)),
		page("h", "/", 200, 1, at(1, 0).AddDate(0, 5, 0)),
		page("h", "/", 200, 1, at(1, 0).AddDate(1, 0, 0)),
	)

	for period, hits := range map[string]int64{
		"2000":                         2,
		"2000-01":                      1,
		at(20, 0).Format("2006-01-02"): 1,
		at(1, 0).AddDate(0, 1, 0).Format("2006-01"): 0,
	} {
		if got := dim(t, db, "h", tagURL, period, Filter{})["/"].Hits; got != hits {
			t.Errorf("Dim(%q) hits of / = %d, want %d", period, got, hits)
		}
	}
}

// A host is read in any case, a long one is clipped, and a host never reads another whose name starts with it.
func TestHosts(t *testing.T) {
	db := openStore(t)
	long := strings.Repeat("h", 40*maxValueLen)
	flush(t, db,
		page("ab", "/", 200, 1, base),
		page("Example.COM", "/", 200, 1, base),
		page("example.com", "/", 200, 1, base),
		page(long, "/", 200, 1, base),
	)

	for host, hits := range map[string]int64{"a": 0, "ab": 1, "EXAMPLE.com": 2, long: 1, long[:maxValueLen]: 1} {
		if got := totals(t, db, host, "2000", Filter{}).Hits; got != hits {
			t.Errorf("Totals of %.20q (%d bytes): %d hits, want %d", host, len(host), got, hits)
		}

		if got := dim(t, db, host, tagURL, "2000", Filter{})["/"].Hits; got != hits {
			t.Errorf("Dim of %.20q (%d bytes): %d hits of /, want %d", host, len(host), got, hits)
		}

		var got int64
		for _, p := range series(t, db, host, tagDay, "2000", Filter{}) {
			got += p.Hits
		}

		if got != hits {
			t.Errorf("Series of %.20q (%d bytes): %d hits, want %d", host, len(host), got, hits)
		}
	}
}

// Hosts lists each host once, in name order, with the months of its first and last days.
func TestHostList(t *testing.T) {
	db := openStore(t)

	if got, err := db.Hosts(); err != nil || len(got) != 0 {
		t.Fatalf("Hosts of an empty store = %+v, %v; want none", got, err)
	}

	early, late := base.AddDate(0, -2, 0), base.AddDate(0, 2, 0)
	flush(t, db,
		page("zz", "/", 200, 1, base),
		page("aaa", "/", 200, 1, late),
		page("aaa", "/", 200, 1, base),
		page("zz", "/", 200, 1, early),
	)

	month := func(d time.Time) string { return d.Format("2006-01") }
	want := []Host{{"aaa", month(base), month(late)}, {"zz", month(early), month(base)}}

	if got, err := db.Hosts(); err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("Hosts = %+v, %v; want %+v", got, err, want)
	}
}

// A day key of another shape fails Hosts.
func TestHostListCorrupt(t *testing.T) {
	db := openStore(t)
	putRaw(t, db, bktAgg, append(encKey(tagDay), 0x80), nil)

	if _, err := db.Hosts(); !errors.Is(err, errBadKey) {
		t.Errorf("Hosts: err = %v, want errBadKey", err)
	}
}

// Bandwidth is capped at math.MaxInt64 across flushes.
func TestBandwidthCappedAcrossFlushes(t *testing.T) {
	db := openStore(t)
	ev := page("h", "/", 200, math.MaxInt64, base)
	flush(t, db, ev)
	flush(t, db, ev)

	got := totals(t, db, "h", "2000", Filter{})
	if got.HitBandwidth != math.MaxInt64 || got.PageBandwidth != math.MaxInt64 {
		t.Errorf("bandwidth = %d, %d of pages; want math.MaxInt64 for both", got.HitBandwidth, got.PageBandwidth)
	}
}

// A flush adds to the stored counters and empties the batch: sketches, pages for the visits and log states included.
func TestFlushAdds(t *testing.T) {
	db := openStore(t)
	ev := from(ip(0), page("h", "/", 200, 3, base))

	b := db.NewBatch(DefaultOptions())
	b.Apply(ev)
	b.SetState("/a.log", LogState{Offset: 1})

	for range 2 {
		if err := db.Flush(b); err != nil {
			t.Fatalf("flush: %v", err)
		}

		if len(b.d) != 0 || len(b.u) != 0 || len(b.events) != 0 || len(b.state) != 0 {
			t.Fatalf("the batch keeps %d counters, %d sketches, %d pages and %d log states after a flush", len(b.d),
				len(b.u), len(b.events), len(b.state))
		}
	}

	flush(t, db, ev)
	flush(t, db)

	if got, want := totals(t, db, "h", "2000", Filter{}), withVisits(pageCounts(2, 6), 1); got != want {
		t.Errorf("Totals = %+v, want %+v", got, want)
	}
}

// A corrupt stored value fails every read of it, and a flush onto it writes nothing and keeps the batch.
func TestCorruptValue(t *testing.T) {
	db := openStore(t)
	putRaw(t, db, bktAgg, timeKey(tagDay, "bad", base.Format("20060102")), []byte{0})
	putRaw(t, db, bktAgg, dimKey(tagURL, "bad", base.Format("200601"), "/"), []byte{0})

	if _, err := db.Totals("bad", "2000", Filter{}); !errors.Is(err, errBadValue) {
		t.Errorf("Totals: err = %v, want errBadValue", err)
	}

	if _, err := db.Series("bad", tagDay, "2000", Filter{}); !errors.Is(err, errBadValue) {
		t.Errorf("Series: err = %v, want errBadValue", err)
	}

	if _, err := db.Dim("bad", tagURL, "2000", Filter{}); !errors.Is(err, errBadValue) {
		t.Errorf("Dim: err = %v, want errBadValue", err)
	}

	b := db.NewBatch(DefaultOptions())
	b.Apply(from(ip(0), page("good", "/", 200, 1, base)))
	b.Apply(page("bad", "/", 200, 1, base))
	b.SetState("/a.log", LogState{Offset: 1})

	if err := db.Flush(b); !errors.Is(err, errBadValue) {
		t.Fatalf("Flush: err = %v, want errBadValue", err)
	}

	if got := totals(t, db, "good", "2000", Filter{}); got != (Counts{}) {
		t.Errorf("Totals of good after the failed flush = %+v, want none", got)
	}

	if got := unique(t, db, "good", "2000", Filter{}); got != 0 {
		t.Errorf("unique visitors of good after the failed flush = %d, want 0", got)
	}

	if s, ok := logState(t, db, "/a.log"); ok {
		t.Errorf("log state after the failed flush = %+v, want none", s)
	}

	repaired := encodeTally(tally{{0, Counts{}}})
	putRaw(t, db, bktAgg, timeKey(tagDay, "bad", base.Format("20060102")), repaired)
	putRaw(t, db, bktAgg, dimKey(tagURL, "bad", base.Format("200601"), "/"), repaired)

	if err := db.Flush(b); err != nil {
		t.Fatalf("Flush after the repair: %v", err)
	}

	if got := totals(t, db, "good", "2000", Filter{}).Hits; got != 1 {
		t.Errorf("hits of good after the repair = %d, want 1", got)
	}

	if got := unique(t, db, "good", "2000", Filter{}); got != 1 {
		t.Errorf("unique visitors of good after the repair = %d, want 1", got)
	}

	if got, ok := logState(t, db, "/a.log"); !ok || got != (LogState{Offset: 1}) {
		t.Errorf("log state after the repair = %+v, %v; want offset 1", got, ok)
	}
}

// Each read refuses a period that is not a year, a month or a day.
func TestBadPeriod(t *testing.T) {
	db := openStore(t)
	period := "2000-13"

	if _, err := db.Totals("h", period, Filter{}); !errors.Is(err, errBadPeriod) {
		t.Errorf("Totals(%q): err = %v, want errBadPeriod", period, err)
	}

	if _, err := db.Series("h", tagDay, period, Filter{}); !errors.Is(err, errBadPeriod) {
		t.Errorf("Series(%q): err = %v, want errBadPeriod", period, err)
	}

	if _, err := db.Dim("h", tagURL, period, Filter{}); !errors.Is(err, errBadPeriod) {
		t.Errorf("Dim(%q): err = %v, want errBadPeriod", period, err)
	}
}

func TestBadFilter(t *testing.T) {
	db := openStore(t)
	bad := Filter{Kind: FileKind + 1}

	if _, err := db.Totals("h", "2000", bad); !errors.Is(err, errBadFilter) {
		t.Errorf("Totals: err = %v, want errBadFilter", err)
	}

	if _, err := db.Series("h", tagDay, "2000", bad); !errors.Is(err, errBadFilter) {
		t.Errorf("Series: err = %v, want errBadFilter", err)
	}

	if _, err := db.Dim("h", tagURL, "2000", bad); !errors.Is(err, errBadFilter) {
		t.Errorf("Dim: err = %v, want errBadFilter", err)
	}
}
