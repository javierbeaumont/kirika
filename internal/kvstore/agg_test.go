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
	"errors"
	"math"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/javierbeaumont/kirika/internal/logparse"
	bolt "go.etcd.io/bbolt"
)

const (
	botUA     = "Googlebot/2.1"
	desktopUA = "Mozilla/5.0 (X11; Linux x86_64)"
	mobileUA  = "Mozilla/5.0 (iPhone)"
)

// The one date the tests write; every other instant is an offset from it.
var base = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)

// Returns hour h of day d of January 2000.
func at(d, h int) time.Time {
	return base.AddDate(0, 0, d-1).Add(time.Duration(h) * time.Hour)
}

// Returns a request of host for path from a desktop browser, answered with status and size at t.
func page(host, path string, status int, size int64, t time.Time) logparse.Event {
	return logparse.Event{Host: host, Path: path, Status: status, Size: size, Time: t, UserAgent: desktopUA}
}

// Returns a store in a fresh directory, closed when the test ends.
func openStore(t *testing.T) *DB {
	t.Helper()

	db, err := Open(filepath.Join(t.TempDir(), "kirika.db"), time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	t.Cleanup(func() { closeStore(t, db) })

	return db
}

// Applies evs in one batch with the default options and flushes it.
func flush(t *testing.T, db *DB, evs ...logparse.Event) {
	t.Helper()

	b := NewBatch(DefaultOptions())
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

// Stores a raw value under key in the agg bucket.
func putRaw(t *testing.T, db *DB, key, v []byte) {
	t.Helper()

	err := db.b.Update(func(tx *bolt.Tx) error { return tx.Bucket(bktAgg).Put(key, v) })
	if err != nil {
		t.Fatalf("put: %v", err)
	}
}

// Returns the counters of n page hits of size bytes in all.
func pageCounts(n, size int64) Counts {
	return Counts{HitBandwidth: size, Hits: n, PageBandwidth: size, Pages: n}
}

// Checks every counter, time series and dimension of a set of human requests in the default view.
func TestApply(t *testing.T) {
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

// Returns the counters stored under key, per class.
func stored(t *testing.T, db *DB, key []byte) tally {
	t.Helper()

	var tl tally

	err := db.b.View(func(tx *bolt.Tx) error {
		var err error

		tl, err = decodeTally(tx.Bucket(bktAgg).Get(key))

		return err
	})
	if err != nil {
		t.Fatalf("read %q: %v", key, err)
	}

	return tl
}

// Checks the class each request is counted in, and its client kind.
func TestClasses(t *testing.T) {
	ua := func(ev logparse.Event, ua string) logparse.Event {
		ev.UserAgent = ua

		return ev
	}

	for _, tc := range []struct {
		name  string
		ev    logparse.Event
		bot   bool
		group int
	}{
		{"200", page("h", "/", 200, 1, base), false, groupCorrect},
		{"206", page("h", "/", 206, 1, base), false, groupCorrect},
		{"304", page("h", "/", 304, 1, base), false, groupCorrect},
		{"100", page("h", "/", 100, 1, base), false, groupOther},
		{"204", page("h", "/", 204, 1, base), false, groupOther},
		{"301", page("h", "/", 301, 1, base), false, groupOther},
		{"399", page("h", "/", 399, 1, base), false, groupOther},
		{"400", page("h", "/", 400, 1, base), false, groupError},
		{"500", page("h", "/", 500, 1, base), false, groupError},
		{"999", page("h", "/", 999, 1, base), false, groupError},
		{"no status", page("h", "/", 0, 1, base), false, groupError},
		{"bot marker", ua(page("h", "/", 200, 1, base), botUA), true, groupCorrect},
		{"empty user agent", ua(page("h", "/", 404, 1, base), ""), true, groupError},
		{"robots.txt", page("h", "/robots.txt", 200, 1, base), true, groupCorrect},
		{"robots.txt in any case", page("h", "/x/ROBOTS.TXT", 200, 1, base), true, groupCorrect},
		{"robots.txt as a prefix", page("h", "/robots.txt.bak", 200, 1, base), false, groupCorrect},
	} {
		db := openStore(t)
		flush(t, db, tc.ev)

		got := stored(t, db, timeKey(tagDay, "h", base.Format("20060102")))
		if want := newClass(tc.bot, tc.group); len(got) != 1 || got[0].class != want {
			t.Errorf("%s: counted in %+v, want class %d only", tc.name, got, want)
		}

		client := "desktop"
		if tc.bot {
			client = "bot"
		}

		all := Filter{Audience: AllAudiences, Status: AllStatuses}
		if got := dim(t, db, "h", tagCli, "2000", all); len(got) != 1 || got[client].HitBandwidth != 1 {
			t.Errorf("%s: clients = %+v, want %s", tc.name, got, client)
		}

		statuses := dim(t, db, "h", tagStat, "2000", all)
		if want := strconv.Itoa(tc.ev.Status); tc.ev.Status == 0 && len(statuses) != 0 ||
			tc.ev.Status != 0 && (len(statuses) != 1 || statuses[want].HitBandwidth != 1) {
			t.Errorf("%s: statuses = %+v, want %q only, or none without a status", tc.name, statuses, want)
		}
	}
}

// A 206 counts a hit only when it starts at byte 0, and its bytes always.
func TestPartialContent(t *testing.T) {
	db := openStore(t)
	first := page("h", "/v.mp4", 206, 100, base)
	first.FirstPart = true
	flush(t, db,
		first,
		page("h", "/v.mp4", 206, 50, base),
		page("h", "/doc", 206, 30, base),
		page("h", "/x.mp4", 200, 5, base),
	)

	want := Counts{HitBandwidth: 185, Hits: 2, PageBandwidth: 30}
	if got := totals(t, db, "h", "2000", Filter{}); got != want {
		t.Errorf("Totals = %+v, want %+v", got, want)
	}
}

// The valid codes are an option: with only 200, a 304 is another status.
func TestValidCodes(t *testing.T) {
	db := openStore(t)

	b := NewBatch(Options{ValidCodes: []int{200}})
	b.Apply(page("h", "/", 200, 1, base))
	b.Apply(page("h", "/", 304, 2, base))

	if err := db.Flush(b); err != nil {
		t.Fatalf("flush: %v", err)
	}

	if got := totals(t, db, "h", "2000", Filter{}); got != pageCounts(1, 1) {
		t.Errorf("Totals = %+v, want the 200 only", got)
	}

	if got := totals(t, db, "h", "2000", Filter{Status: AllStatuses}); got != pageCounts(2, 3) {
		t.Errorf("Totals of every status = %+v, want both", got)
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
	}
}

// Bandwidth is capped at math.MaxInt64, within a batch and across flushes.
func TestBandwidthCapped(t *testing.T) {
	db := openStore(t)
	ev := page("h", "/", 200, math.MaxInt64, base)
	flush(t, db, ev, ev)
	flush(t, db, ev)

	got := totals(t, db, "h", "2000", Filter{})
	if got.HitBandwidth != math.MaxInt64 || got.PageBandwidth != math.MaxInt64 {
		t.Errorf("bandwidth = %d, %d of pages; want math.MaxInt64 for both", got.HitBandwidth, got.PageBandwidth)
	}
}

// A flush adds to the stored counters and empties the batch.
func TestFlushAdds(t *testing.T) {
	db := openStore(t)
	ev := page("h", "/", 200, 3, base)

	b := NewBatch(DefaultOptions())
	b.Apply(ev)

	for range 2 {
		if err := db.Flush(b); err != nil {
			t.Fatalf("flush: %v", err)
		}
	}

	flush(t, db, ev)
	flush(t, db)

	if got, want := totals(t, db, "h", "2000", Filter{}), pageCounts(2, 6); got != want {
		t.Errorf("Totals = %+v, want %+v", got, want)
	}
}

// A corrupt stored value fails every read of it, and a flush onto it writes nothing and keeps the batch.
func TestCorruptValue(t *testing.T) {
	db := openStore(t)
	putRaw(t, db, timeKey(tagDay, "bad", base.Format("20060102")), []byte{0})
	putRaw(t, db, dimKey(tagURL, "bad", base.Format("200601"), "/"), []byte{0})

	if _, err := db.Totals("bad", "2000", Filter{}); !errors.Is(err, errBadValue) {
		t.Errorf("Totals: err = %v, want errBadValue", err)
	}

	if _, err := db.Series("bad", tagDay, "2000", Filter{}); !errors.Is(err, errBadValue) {
		t.Errorf("Series: err = %v, want errBadValue", err)
	}

	if _, err := db.Dim("bad", tagURL, "2000", Filter{}); !errors.Is(err, errBadValue) {
		t.Errorf("Dim: err = %v, want errBadValue", err)
	}

	b := NewBatch(DefaultOptions())
	b.Apply(page("good", "/", 200, 1, base))
	b.Apply(page("bad", "/", 200, 1, base))

	if err := db.Flush(b); !errors.Is(err, errBadValue) {
		t.Fatalf("Flush: err = %v, want errBadValue", err)
	}

	if got := totals(t, db, "good", "2000", Filter{}); got != (Counts{}) {
		t.Errorf("Totals of good after the failed flush = %+v, want none", got)
	}

	repaired := encodeTally(tally{{0, Counts{}}})
	putRaw(t, db, timeKey(tagDay, "bad", base.Format("20060102")), repaired)
	putRaw(t, db, dimKey(tagURL, "bad", base.Format("200601"), "/"), repaired)

	if err := db.Flush(b); err != nil {
		t.Fatalf("Flush after the repair: %v", err)
	}

	if got := totals(t, db, "good", "2000", Filter{}).Hits; got != 1 {
		t.Errorf("hits of good after the repair = %d, want 1", got)
	}
}

func TestBadPeriod(t *testing.T) {
	db := openStore(t)

	for _, period := range []string{
		"", "00", "200001", "2000/01", "20-00", "abcd", "2000-1", "2000-13", "2000-01-32", " 2000",
	} {
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

func TestClip(t *testing.T) {
	ascii := "/" + strings.Repeat("x", 2*maxValueLen)

	for _, tc := range []struct {
		name, s string
		want    int
	}{
		{"ASCII", ascii, maxValueLen},
		{"a value at the limit", strings.Repeat("x", maxValueLen), maxValueLen},
		// After "/", byte maxValueLen is the second of a 2-byte character and the fourth of a 4-byte one. In the bytes
		// that are not UTF-8, the last "/" before it is 4 bytes back, too far to start a character that holds it.
		{"2-byte characters", "/" + strings.Repeat("\u00f1", maxValueLen), maxValueLen - 1},
		{"4-byte characters", "/" + strings.Repeat("\U0001F600", maxValueLen), maxValueLen - 3},
		{"bytes that are not UTF-8", strings.Repeat("/\x80\x80\x80\x80", maxValueLen), maxValueLen},
	} {
		if got := clip(tc.s); got != tc.s[:tc.want] {
			t.Errorf("clip of %s is %d bytes, want %d", tc.name, len(got), tc.want)
		}
	}

	db := openStore(t)
	ev := page("h", ascii, 200, 1, base)
	ev.Referer = ascii
	flush(t, db, ev)

	for _, tag := range []string{tagURL, tagRef} {
		if got := dim(t, db, "h", tag, "2000-01", Filter{}); got[ascii[:maxValueLen]].Hits != 1 {
			t.Errorf("Dim(%q) = %d values, want the clipped one", tag, len(got))
		}
	}
}
