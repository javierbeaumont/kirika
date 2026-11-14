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
	"testing"
	"time"

	"github.com/javierbeaumont/kirika/internal/logparse"
	bolt "go.etcd.io/bbolt"
)

// Returns a correct page request of host from client to path at t.
func req(host, client, path string, t time.Time) logparse.Event {
	return from(client, page(host, path, 200, 1, t))
}

// Returns the number of stored sessions.
func sessionCount(t *testing.T, db *DB) int {
	t.Helper()

	var n int

	err := db.b.View(func(tx *bolt.Tx) error {
		n = tx.Bucket(bktSess).Stats().KeyN

		return nil
	})
	if err != nil {
		t.Fatalf("view: %v", err)
	}

	return n
}

// A page opens a visit when it is its client's first, or more than the timeout after the previous one, whatever the
// client's form.
func TestVisits(t *testing.T) {
	db := openStore(t)
	t0 := at(1, 10)
	flush(t, db,
		req("h", "192.0.2.1", "/", t0),
		req("h", "::ffff:192.0.2.1", "/", t0.Add(time.Hour)),
		req("h", "192.0.2.1", "/", t0.Add(2*time.Hour+time.Second)),
		req("h", "192.0.2.2", "/", t0),
		req("other", "192.0.2.1", "/", t0.Add(2*time.Hour+time.Second)),
		page("h", "/", 200, 1, t0),
	)

	if got := totals(t, db, "h", "2000-01", Filter{}).Visits; got != 3 {
		t.Errorf("visits of h = %d, want 3", got)
	}

	if got := totals(t, db, "other", "2000-01", Filter{}).Visits; got != 1 {
		t.Errorf("visits of other = %d, want 1", got)
	}

	hour := func(h int) string { return t0.Add(time.Duration(h) * time.Hour).Format("2006010215") }
	want := []TimePoint{
		{hour(0), withVisits(pageCounts(3, 3), 2)},
		{hour(1), pageCounts(1, 1)},
		{hour(2), withVisits(pageCounts(1, 1), 1)},
	}

	if got := series(t, db, "h", tagHour, "2000-01-01", Filter{}); !reflect.DeepEqual(got, want) {
		t.Errorf("hour series = %+v, want %+v", got, want)
	}
}

// Only correct pages take part in visits, with one session per client and audience: a browser and a bot on one address
// make a visit each, and an error or a redirect makes none. Visits show with pages but not files, and under Status All
// they equal Correct's.
func TestVisitClasses(t *testing.T) {
	db := openStore(t)

	bot := req("h", "192.0.2.1", "/", base)
	bot.UserAgent = botUA

	flush(t, db,
		req("h", "192.0.2.1", "/", base),
		bot,
		from("192.0.2.2", page("h", "/missing", 404, 1, base)),
		from("192.0.2.3", page("h", "/moved", 301, 1, base)),
	)

	for _, tc := range []struct {
		f    Filter
		want int64
	}{
		{Filter{}, 1},
		{Filter{Audience: Bots}, 1},
		{Filter{Audience: AllAudiences}, 2},
		{Filter{Status: Errors}, 0},
		{Filter{Status: AllStatuses}, 1},
		{Filter{Kind: PageKind}, 1},
		{Filter{Kind: FileKind}, 0},
	} {
		if got := totals(t, db, "h", "2000", tc.f).Visits; got != tc.want {
			t.Errorf("visits with %+v = %d, want %d", tc.f, got, tc.want)
		}
	}

	if got := sessionCount(t, db); got != 2 {
		t.Errorf("%d sessions, want 2", got)
	}
}

// A visit counts in the hour, day and month of the store's zone, and its exit in the month it ended there.
func TestVisitZone(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "kirika.db"), time.Second, "Asia/Kolkata")
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	t.Cleanup(func() { closeStore(t, db) })

	first := base.Add(-5*time.Hour - 30*time.Minute) // the first instant of 2000 in Kolkata
	flush(t, db, req("h", "192.0.2.1", "/a", first), req("h", "192.0.2.2", "/b", first.Add(2*time.Hour)))

	if got := series(t, db, "h", tagHour, "2000-01-01", Filter{}); len(got) == 0 || got[0].At != "2000010100" ||
		got[0].Visits != 1 {
		t.Errorf("hour series = %+v, want a visit in the first hour of 2000", got)
	}

	want := map[string]Counts{"/a": {Visits: 1}, "/b": {Visits: 1}}
	if got := dim(t, db, "h", tagEntry, "2000-01", Filter{}); !reflect.DeepEqual(got, want) {
		t.Errorf("entry pages = %+v, want %+v", got, want)
	}

	want = map[string]Counts{"/a": {Visits: 1}}
	if got := dim(t, db, "h", tagExit, "2000-01", Filter{}); !reflect.DeepEqual(got, want) {
		t.Errorf("exit pages = %+v, want %+v", got, want)
	}
}

// A session carries over between batches, by the log's time: these requests are years older than the clock.
func TestVisitAcrossFlushes(t *testing.T) {
	db := openStore(t)

	for _, m := range []time.Duration{0, 30, 60, 121} {
		flush(t, db, req("h", "192.0.2.1", "/", base.Add(m*time.Minute)))
	}

	if got := totals(t, db, "h", "2000", Filter{}).Visits; got != 2 {
		t.Errorf("visits = %d, want 2", got)
	}
}

// A flush with no page closes no visit, at a negative Unix time too: a client's pages on either side of it make one
// visit.
func TestFlushWithoutPages(t *testing.T) {
	for _, t0 := range []time.Time{at(1, 10), at(1, 10).AddDate(-50, 0, 0)} {
		db := openStore(t)
		flush(t, db, req("h", "192.0.2.1", "/", t0))
		flush(t, db, req("h", "192.0.2.1", "/logo.png", t0.Add(time.Minute)))
		flush(t, db, req("h", "192.0.2.1", "/", t0.Add(2*time.Minute)))

		if got := totals(t, db, "h", t0.Format("2006-01"), Filter{}).Visits; got != 1 {
			t.Errorf("visits in %s = %d, want 1", t0.Format("2006-01"), got)
		}
	}
}

// A bot's visit counts its exit under bots only.
func TestBotExit(t *testing.T) {
	db := openStore(t)
	bot := req("h", "192.0.2.1", "/a", at(1, 10))
	bot.UserAgent = botUA
	flush(t, db, bot)
	flush(t, db, req("h", "192.0.2.2", "/", at(1, 12)))

	for filter, want := range map[Filter]int64{{Audience: Bots}: 1, {}: 0} {
		if got := dim(t, db, "h", tagExit, "2000-01", filter)["/a"].Visits; got != want {
			t.Errorf("exits of /a in %+v = %d, want %d", filter, got, want)
		}
	}
}

// A visit enters on its first page and exits on its latest, files take no part, and an idle session ends and is
// deleted.
func TestEntryExit(t *testing.T) {
	db := openStore(t)
	t0 := at(1, 10)
	flush(t, db,
		req("h", "192.0.2.1", "/a", t0),
		req("h", "192.0.2.1", "/b", t0.Add(time.Minute)),
		req("h", "192.0.2.1", "/logo.png", t0.Add(2*time.Minute)),
		req("h", "192.0.2.2", "/logo.png", t0),
	)

	if got := dim(t, db, "h", tagExit, "2000-01", Filter{}); len(got) != 0 {
		t.Errorf("exit pages of open visits = %+v, want none", got)
	}

	flush(t, db, req("h", "192.0.2.3", "/c", t0.Add(time.Hour+3*time.Minute)))

	want := map[string]Counts{"/b": {Visits: 1}}
	if got := dim(t, db, "h", tagExit, "2000-01", Filter{}); !reflect.DeepEqual(got, want) {
		t.Errorf("exit pages = %+v, want %+v", got, want)
	}

	want = map[string]Counts{"/a": {Visits: 1}, "/c": {Visits: 1}}
	if got := dim(t, db, "h", tagEntry, "2000-01", Filter{}); !reflect.DeepEqual(got, want) {
		t.Errorf("entry pages = %+v, want %+v", got, want)
	}

	if got := totals(t, db, "h", "2000-01", Filter{}).Visits; got != 2 {
		t.Errorf("visits = %d, want 2", got)
	}

	if got := sessionCount(t, db); got != 1 {
		t.Errorf("%d sessions left, want 1", got)
	}
}

// Entry and exit pages are counted as the URLs are: without their query, and an index page under its directory.
func TestEntryExitPaths(t *testing.T) {
	db := openStore(t)
	flush(t, db, req("h", "192.0.2.1", "/index.html?from=x", base), req("h", "192.0.2.2", "/", base.Add(2*time.Hour)))

	want := map[string]Counts{"/": {Visits: 2}}
	if got := dim(t, db, "h", tagEntry, "2000-01", Filter{}); !reflect.DeepEqual(got, want) {
		t.Errorf("entry pages = %+v, want %+v", got, want)
	}

	want = map[string]Counts{"/": {Visits: 1}}
	if got := dim(t, db, "h", tagExit, "2000-01", Filter{}); !reflect.DeepEqual(got, want) {
		t.Errorf("exit pages = %+v, want %+v", got, want)
	}
}

// A flush ends visits by their host's newest page in the batch: a log's lines can come out of order.
func TestEndByHostNewest(t *testing.T) {
	db := openStore(t)
	t0 := at(1, 10)
	flush(t, db, req("h", "192.0.2.1", "/a", t0.Add(30*time.Minute)))
	flush(t, db, req("h", "192.0.2.2", "/b", t0.Add(2*time.Hour)), req("h", "192.0.2.3", "/c", t0))

	want := map[string]Counts{"/a": {Visits: 1}, "/c": {Visits: 1}}
	if got := dim(t, db, "h", tagExit, "2000-01", Filter{}); !reflect.DeepEqual(got, want) {
		t.Errorf("exit pages = %+v, want %+v", got, want)
	}

	if got := sessionCount(t, db); got != 1 {
		t.Errorf("%d sessions, want 1", got)
	}
}

// A visit ahead of a flush's pages stays open, and its client's pages behind it open visits of their own; one more than
// 31 days ahead ends, as after lines from a clock that jumped a year.
func TestVisitAhead(t *testing.T) {
	db := openStore(t)
	yearAhead := at(1, 10).AddDate(1, 0, 0)
	flush(t, db, req("h", "192.0.2.9", "/a", yearAhead))
	flush(t, db, req("h", "192.0.2.1", "/a", at(2, 10)))
	flush(t, db, req("h", "192.0.2.1", "/b", at(1, 10)))
	flush(t, db, req("h", "192.0.2.1", "/c", at(2, 10).Add(10*time.Minute)))

	if got := totals(t, db, "h", "2000-01", Filter{}).Visits; got != 2 {
		t.Errorf("visits = %d, want 2", got)
	}

	want := map[string]Counts{"/b": {Visits: 1}}
	if got := dim(t, db, "h", tagExit, "2000-01", Filter{}); !reflect.DeepEqual(got, want) {
		t.Errorf("exit pages = %+v, want %+v", got, want)
	}

	want = map[string]Counts{"/a": {Visits: 1}}
	if got := dim(t, db, "h", tagExit, yearAhead.Format("2006-01"), Filter{}); !reflect.DeepEqual(got, want) {
		t.Errorf("exit pages a year ahead = %+v, want %+v", got, want)
	}

	if got := sessionCount(t, db); got != 1 {
		t.Errorf("%d sessions, want 1", got)
	}
}

// An older log read after a newer one counts its own visits and, within 31 days, ends none of the newer: their next
// pages join them.
func TestOldLogAfterNew(t *testing.T) {
	db := openStore(t)
	newer := at(1, 10).AddDate(0, 1, 0)
	flush(t, db, req("h", "192.0.2.1", "/new", newer))
	flush(t, db, req("h", "192.0.2.1", "/a", at(1, 10)), req("h", "192.0.2.1", "/b", at(1, 10).Add(10*time.Minute)))
	flush(t, db, req("h", "192.0.2.1", "/next", newer.Add(10*time.Minute)))

	for month, want := range map[string]int64{"2000-01": 1, newer.Format("2006-01"): 1} {
		if got := totals(t, db, "h", month, Filter{}).Visits; got != want {
			t.Errorf("visits of %s = %d, want %d", month, got, want)
		}
	}

	if got := dim(t, db, "h", tagExit, "2000-01", Filter{})["/b"].Visits; got != 1 {
		t.Errorf("exits of /b = %d, want 1", got)
	}

	if got := dim(t, db, "h", tagExit, newer.Format("2006-01"), Filter{}); len(got) != 0 {
		t.Errorf("exit pages of the newer month = %+v, want none", got)
	}
}

// Within 31 days, a flush ends no visit of a host it has no page of: a quiet host's log read after a busy one's goes on
// with its visits, and so do the busy host's next pages.
func TestQuietHostAfterBusy(t *testing.T) {
	db := openStore(t)
	flush(t, db, req("quiet", "192.0.2.1", "/a", at(1, 10)))
	flush(t, db, req("busy", "192.0.2.2", "/x", at(1, 12)))
	flush(t, db, req("quiet", "192.0.2.1", "/b", at(1, 10).Add(30*time.Minute)))
	flush(t, db, req("busy", "192.0.2.2", "/y", at(1, 12).Add(10*time.Minute)))

	for _, host := range []string{"quiet", "busy"} {
		if got := totals(t, db, host, "2000-01", Filter{}).Visits; got != 1 {
			t.Errorf("visits of %s = %d, want 1", host, got)
		}
	}
}

// A visit more than 31 days behind a flush's newest page ends, whatever its host, and its session is deleted.
func TestAbandonedVisit(t *testing.T) {
	db := openStore(t)
	monthOn := at(1, 10).AddDate(0, 1, 0) // January has 31 days
	flush(t, db, req("quiet", "192.0.2.1", "/a", at(1, 10)))
	flush(t, db, req("busy", "192.0.2.2", "/x", monthOn))

	if got := sessionCount(t, db); got != 2 {
		t.Errorf("%d sessions 31 days on, want 2", got)
	}

	flush(t, db, req("busy", "192.0.2.2", "/y", monthOn.Add(time.Second)))

	if got := dim(t, db, "quiet", tagExit, "2000-01", Filter{})["/a"].Visits; got != 1 {
		t.Errorf("exits of /a = %d, want 1", got)
	}

	if got := sessionCount(t, db); got != 1 {
		t.Errorf("%d sessions a second later, want 1", got)
	}
}

// An exit counts in the month its visit ended, even when a later month closes it.
func TestExitMonth(t *testing.T) {
	db := openStore(t)
	end := base.AddDate(0, 1, 0).Add(-10 * time.Minute)
	flush(t, db, req("h", "192.0.2.1", "/a", end), req("h", "192.0.2.2", "/", end.Add(2*time.Hour)))

	if got := dim(t, db, "h", tagExit, "2000-01", Filter{})["/a"].Visits; got != 1 {
		t.Errorf("exits of /a in its month = %d, want 1", got)
	}
}

// A request older than its visit's latest moves neither its time nor its exit.
func TestOutOfOrder(t *testing.T) {
	db := openStore(t)
	flush(t, db,
		req("h", "192.0.2.1", "/b", at(1, 10).Add(5*time.Minute)),
		req("h", "192.0.2.1", "/a", at(1, 10)),
		req("h", "192.0.2.1", "/c", at(1, 11).Add(4*time.Minute)),
		req("h", "192.0.2.1", "/d", at(1, 11)),
	)
	flush(t, db, req("h", "192.0.2.2", "/", at(1, 13)))

	if got := totals(t, db, "h", "2000-01", Filter{}).Visits; got != 2 {
		t.Errorf("visits = %d, want 2", got)
	}

	if got := dim(t, db, "h", tagExit, "2000-01", Filter{}); got["/c"].Visits != 1 || len(got) != 1 {
		t.Errorf("exit pages = %+v, want /c", got)
	}
}

// Of two pages in the same second, the later in the log is the visit's exit.
func TestSameSecondExit(t *testing.T) {
	db := openStore(t)
	flush(t, db, req("h", "192.0.2.1", "/a", base), req("h", "192.0.2.1", "/b", base))
	flush(t, db, req("h", "192.0.2.2", "/", base.Add(2*time.Hour)))

	want := map[string]Counts{"/b": {Visits: 1}}
	if got := dim(t, db, "h", tagExit, "2000-01", Filter{}); !reflect.DeepEqual(got, want) {
		t.Errorf("exit pages = %+v, want %+v", got, want)
	}
}

// Retrying a failed flush counts its visits once.
func TestVisitsOnce(t *testing.T) {
	db := openStore(t)
	key := dimKey(tagURL, "h", base.Format("200601"), "/")
	putRaw(t, db, bktAgg, key, []byte{0})

	b := db.NewBatch(DefaultOptions())
	b.Apply(req("h", "192.0.2.1", "/", at(1, 10)))

	if err := db.Flush(b); !errors.Is(err, errBadValue) {
		t.Fatalf("Flush: err = %v, want errBadValue", err)
	}

	putRaw(t, db, bktAgg, key, encodeTally(tally{{0, Counts{}}}))

	if err := db.Flush(b); err != nil {
		t.Fatalf("Flush after the repair: %v", err)
	}

	if got := totals(t, db, "h", "2000-01", Filter{}).Visits; got != 1 {
		t.Errorf("visits = %d, want 1", got)
	}
}

// An unreadable session, as one of another format or at a time no log holds, counts as none, and the next flush deletes
// it.
func TestUnreadableSession(t *testing.T) {
	farPast := encodeSession(session{class: humanVisits, host: "h", visits: []visit{{"/x", math.MinInt64}}})

	for name, value := range map[string][]byte{"another format": {0}, "a time out of range": farPast} {
		db := openStore(t)
		putRaw(t, db, bktSess, sessionID(db.salt, "h", "192.0.2.1", humanVisits), value)
		putRaw(t, db, bktSess, sessionID(db.salt, "h", "192.0.2.9", humanVisits), value)
		flush(t, db, req("h", "192.0.2.1", "/", at(1, 10)))

		if got := totals(t, db, "h", "2000-01", Filter{}).Visits; got != 1 {
			t.Errorf("%s: visits = %d, want 1", name, got)
		}

		if got := sessionCount(t, db); got != 1 {
			t.Errorf("%s: %d sessions, want 1", name, got)
		}
	}
}

// The timeout compares whole seconds, as a session keeps them: pages at seconds 0.9 and 3600.5 make one visit.
func TestVisitWholeSeconds(t *testing.T) {
	db := openStore(t)
	flush(t, db, req("h", "192.0.2.1", "/", base.Add(900*time.Millisecond)))
	flush(t, db, req("h", "192.0.2.1", "/", base.Add(time.Hour+500*time.Millisecond)))

	if got := totals(t, db, "h", "2000", Filter{}).Visits; got != 1 {
		t.Errorf("visits = %d, want 1", got)
	}
}

// Visits work the same at negative Unix times: an NCSA log may go back to the year 1000.
func TestVisitBefore1970(t *testing.T) {
	db := openStore(t)
	old := base.AddDate(-50, 0, 0)
	flush(t, db, req("h", "192.0.2.1", "/", old))
	flush(t, db, req("h", "192.0.2.1", "/", old.Add(10*time.Minute)))

	if got := totals(t, db, "h", old.Format("2006"), Filter{}).Visits; got != 1 {
		t.Errorf("visits = %d, want 1", got)
	}

	flush(t, db, req("h", "192.0.2.2", "/", old.Add(2*time.Hour)))

	if got := sessionCount(t, db); got != 1 {
		t.Errorf("%d sessions after another client's page 2 hours on, want 1", got)
	}
}

// The visit timeout is the batch's: with 30 minutes, two pages 45 minutes apart make two visits.
func TestVisitTimeout(t *testing.T) {
	db := openStore(t)

	o := DefaultOptions()
	o.VisitTimeout = 30 * time.Minute

	b := db.NewBatch(o)
	b.Apply(req("h", "192.0.2.1", "/", base))
	b.Apply(req("h", "192.0.2.1", "/", base.Add(45*time.Minute)))

	if err := db.Flush(b); err != nil {
		t.Fatalf("flush: %v", err)
	}

	if got := totals(t, db, "h", "2000", Filter{}).Visits; got != 2 {
		t.Errorf("visits = %d, want 2", got)
	}

	if got := dim(t, db, "h", tagExit, "2000-01", Filter{})["/"].Visits; got != 1 {
		t.Errorf("exits = %d, want 1: the timeout ends the first visit", got)
	}
}
