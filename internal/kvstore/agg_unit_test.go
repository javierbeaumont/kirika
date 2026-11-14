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

//go:build unit

package kvstore

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/javierbeaumont/kirika/internal/logparse"
	"github.com/javierbeaumont/kirika/internal/uaclass"
)

// Returns an empty batch, with no store, that counts by the rules of o in loc.
func batchIn(loc *time.Location, o Options) *Batch {
	return (&DB{loc: loc}).NewBatch(o)
}

// Returns a batch in UTC with the default options and evs applied.
func applied(evs ...logparse.Event) *Batch {
	b := batchIn(time.UTC, DefaultOptions())
	for _, ev := range evs {
		b.Apply(ev)
	}

	return b
}

// Returns the counters of each key of the batch that starts with prefix and holds a class f counts, by the rest of the
// key.
func counted(b *Batch, prefix []byte, f Filter) map[string]Counts {
	out := map[string]Counts{}

	for k, t := range b.d {
		rest, found := strings.CutPrefix(k, string(prefix))
		if c, ok := f.sum(t); found && ok {
			out[rest] = c
		}
	}

	return out
}

// A request counts in its host's hour and day, and in its month's path, status, referrer and client kind. An empty host
// counts as unknown.
func TestApply(t *testing.T) {
	referred := page("a.example", "/", 200, 10, at(1, 10))
	referred.Referer = "https://r.example/"
	mobile := page("a.example", "/", 200, 10, at(1, 10))
	mobile.UserAgent = mobileUA
	jan, feb := at(1, 0), at(1, 0).AddDate(0, 1, 0)
	b := applied(
		referred,
		mobile,
		page("a.example", "/logo.png", 304, 0, at(1, 11)),
		page("a.example", "/blog", 200, 20, at(2, 0)),
		page("", "/", 200, 5, at(2, 0)),
		page("a.example", "/", 200, 7, feb),
	)

	hour := func(host string, tm time.Time) string { return string(timeKey(tagHour, host, tm.Format("2006010215"))) }
	day := func(host string, tm time.Time) string { return string(timeKey(tagDay, host, tm.Format("20060102"))) }
	dim := func(tag, host string, tm time.Time, v string) string {
		return string(dimKey(tag, host, tm.Format("200601"), v))
	}

	want := map[string]Counts{
		hour("a.example", at(1, 10)):                        pageCounts(2, 20),
		hour("a.example", at(1, 11)):                        {Hits: 1},
		hour("a.example", at(2, 0)):                         pageCounts(1, 20),
		hour("a.example", feb):                              pageCounts(1, 7),
		hour("unknown", at(2, 0)):                           pageCounts(1, 5),
		day("a.example", jan):                               {HitBandwidth: 20, Hits: 3, PageBandwidth: 20, Pages: 2},
		day("a.example", at(2, 0)):                          pageCounts(1, 20),
		day("a.example", feb):                               pageCounts(1, 7),
		day("unknown", at(2, 0)):                            pageCounts(1, 5),
		dim(tagURL, "a.example", jan, "/"):                  pageCounts(2, 20),
		dim(tagURL, "a.example", jan, "/logo.png"):          {Hits: 1},
		dim(tagURL, "a.example", jan, "/blog"):              pageCounts(1, 20),
		dim(tagURL, "a.example", feb, "/"):                  pageCounts(1, 7),
		dim(tagURL, "unknown", jan, "/"):                    pageCounts(1, 5),
		dim(tagStat, "a.example", jan, "200"):               pageCounts(3, 40),
		dim(tagStat, "a.example", jan, "304"):               {Hits: 1},
		dim(tagStat, "a.example", feb, "200"):               pageCounts(1, 7),
		dim(tagStat, "unknown", jan, "200"):                 pageCounts(1, 5),
		dim(tagRef, "a.example", jan, "https://r.example/"): pageCounts(1, 10),
		dim(tagCli, "a.example", jan, "desktop"):            {HitBandwidth: 30, Hits: 3, PageBandwidth: 30, Pages: 2},
		dim(tagCli, "a.example", jan, "mobile"):             pageCounts(1, 10),
		dim(tagCli, "a.example", feb, "desktop"):            pageCounts(1, 7),
		dim(tagCli, "unknown", jan, "desktop"):              pageCounts(1, 5),
	}

	got := counted(b, nil, Filter{})
	for k, c := range want {
		if got[k] != c {
			t.Errorf("%q = %+v, want %+v", k, got[k], c)
		}
	}

	for k, c := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("%q = %+v, want none", k, c)
		}
	}
}

// Checks the class each request is counted in, and its client kind.
func TestClasses(t *testing.T) {
	withUserAgent := func(event logparse.Event, userAgent string) logparse.Event {
		event.UserAgent = userAgent

		return event
	}
	withoutUserAgent := func(event logparse.Event) logparse.Event {
		event.HasUserAgent, event.UserAgent = false, ""

		return event
	}

	for _, tc := range []struct {
		name  string
		event logparse.Event
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
		{"bot marker", withUserAgent(page("h", "/", 200, 1, base), botUA), true, groupCorrect},
		{"empty user agent", withUserAgent(page("h", "/", 404, 1, base), ""), true, groupError},
		{"no user agent in the log", withoutUserAgent(page("h", "/", 404, 1, base)), false, groupError},
		{"robots.txt", page("h", "/robots.txt", 200, 1, base), true, groupCorrect},
		{"robots.txt in any case", page("h", "/x/ROBOTS.TXT", 200, 1, base), true, groupCorrect},
		{"robots.txt as a prefix", page("h", "/robots.txt.bak", 200, 1, base), false, groupCorrect},
		{
			"robots.txt with no user agent in the log", withoutUserAgent(page("h", "/robots.txt", 200, 1, base)), true,
			groupCorrect,
		},
	} {
		batch := applied(tc.event)

		got := batch.d[string(timeKey(tagDay, "h", base.Format("20060102")))]
		if want := newClass(tc.bot, tc.group); len(got) != 1 || got[0].class != want {
			t.Errorf("%s: counted in %+v, want class %d only", tc.name, got, want)
		}

		clientKind := uaclass.Desktop

		switch {
		case tc.bot:
			clientKind = uaclass.Bot
		case !tc.event.HasUserAgent:
			clientKind = uaclass.Unknown
		}

		all := Filter{Audience: AllAudiences, Status: AllStatuses}
		month := base.Format("200601")

		if got := counted(batch, encKey(tagCli, "h", month), all); len(got) != 1 || got[clientKind].HitBandwidth != 1 {
			t.Errorf("%s: clients = %+v, want %s", tc.name, got, clientKind)
		}

		statuses := counted(batch, encKey(tagStat, "h", month), all)
		if want := strconv.Itoa(tc.event.Status); tc.event.Status == 0 && len(statuses) != 0 ||
			tc.event.Status != 0 && (len(statuses) != 1 || statuses[want].HitBandwidth != 1) {
			t.Errorf("%s: statuses = %+v, want %q only, or none without a status", tc.name, statuses, want)
		}
	}
}

// A 206 counts a hit only when it starts at byte 0, and its bytes always.
func TestPartialContent(t *testing.T) {
	first := page("h", "/v.mp4", 206, 100, base)
	first.FirstPart = true
	b := applied(
		first,
		page("h", "/v.mp4", 206, 50, base),
		page("h", "/doc", 206, 30, base),
		page("h", "/x.mp4", 200, 5, base),
	)

	want := map[string]Counts{base.Format("20060102"): {HitBandwidth: 185, Hits: 2, PageBandwidth: 30}}
	if got := counted(b, encKey(tagDay, "h"), Filter{}); !reflect.DeepEqual(got, want) {
		t.Errorf("days = %+v, want %+v", got, want)
	}
}

// Hours, days and months are those of the batch's zone: the first instant of 2000 in each zone counts in its first hour
// of 2000. The zones lie behind and ahead of UTC, by whole hours or not, and one is on daylight saving time.
func TestZone(t *testing.T) {
	for _, tc := range []struct {
		zone   string
		offset time.Duration // from UTC, in January 2000
	}{
		{"America/New_York", -5 * time.Hour},
		{"UTC", 0},
		{"Europe/Madrid", time.Hour},
		{"Asia/Kolkata", 5*time.Hour + 30*time.Minute},
		{"Asia/Kathmandu", 5*time.Hour + 45*time.Minute},
		{"Pacific/Auckland", 13 * time.Hour},
	} {
		loc, err := time.LoadLocation(tc.zone)
		if err != nil {
			t.Fatalf("load %s: %v", tc.zone, err)
		}

		b := batchIn(loc, DefaultOptions())
		b.Apply(page("h", "/", 200, 1, base.Add(-tc.offset)))

		for _, c := range []struct {
			what   string
			prefix []byte
			want   string
		}{
			{"hours", encKey(tagHour, "h"), "2000010100"},
			{"days", encKey(tagDay, "h"), "20000101"},
			{"paths", encKey(tagURL, "h", "200001"), "/"},
		} {
			want := map[string]Counts{c.want: pageCounts(1, 1)}
			if got := counted(b, c.prefix, Filter{}); !reflect.DeepEqual(got, want) {
				t.Errorf("%s in %s = %+v, want %+v", c.what, tc.zone, got, want)
			}
		}
	}
}

// A daylight saving change merges two hours into one or leaves one empty. In Madrid, the clock goes back from 03:00 to
// 02:00 on the last Sunday of October, and forward from 02:00 to 03:00 on the last Sunday of March, both at 01:00 UTC.
func TestDaylightSaving(t *testing.T) {
	madrid, err := time.LoadLocation("Europe/Madrid")
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	b := batchIn(madrid, DefaultOptions())
	back, forward := base.AddDate(0, 9, 28), base.AddDate(0, 2, 25)

	for _, hour := range []time.Time{back, back.Add(time.Hour), forward, forward.Add(time.Hour)} {
		b.Apply(page("h", "/", 200, 1, hour.Add(30*time.Minute)))
	}

	for _, tc := range []struct {
		day   time.Time
		hours map[string]int64
	}{
		{back, map[string]int64{"02": 2}},
		{forward, map[string]int64{"01": 1, "03": 1}},
	} {
		got := map[string]int64{}
		for hour, c := range counted(b, timeKey(tagHour, "h", tc.day.Format("20060102")), Filter{}) {
			got[hour] = c.Hits
		}

		if !reflect.DeepEqual(got, tc.hours) {
			t.Errorf("hits per hour of %s = %v, want %v", tc.day.Format("January"), got, tc.hours)
		}
	}
}

// The valid codes are an option: with only 200, a 304 is another status.
func TestValidCodes(t *testing.T) {
	b := batchIn(time.UTC, Options{ValidCodes: []int{200}, VisitTimeout: DefaultVisitTimeout})
	b.Apply(page("h", "/", 200, 1, base))
	b.Apply(page("h", "/", 304, 2, base))

	day := base.Format("20060102")

	if got := counted(b, encKey(tagDay, "h"), Filter{})[day]; got != pageCounts(1, 1) {
		t.Errorf("day = %+v, want the 200 only", got)
	}

	if got := counted(b, encKey(tagDay, "h"), Filter{Status: AllStatuses})[day]; got != pageCounts(2, 3) {
		t.Errorf("day of every status = %+v, want both", got)
	}
}

// An index page counts under its directory, with the default index pages or others, and a file never does.
func TestIndexPages(t *testing.T) {
	ym := base.Format("200601")
	b := applied(
		page("h", "/", 200, 1, base),
		page("h", "/index.html", 200, 1, base),
		page("h", "/blog/index.php", 200, 1, base),
		page("h", "/myindex.html", 200, 1, base),
	)

	want := map[string]Counts{"/": pageCounts(2, 2), "/blog/": pageCounts(1, 1), "/myindex.html": pageCounts(1, 1)}
	if got := counted(b, encKey(tagURL, "h", ym), Filter{}); !reflect.DeepEqual(got, want) {
		t.Errorf("paths with the default index pages = %+v, want %+v", got, want)
	}

	b = batchIn(time.UTC, Options{
		IndexPages: []string{"default.htm", "index.png"}, ValidCodes: []int{200}, VisitTimeout: DefaultVisitTimeout,
	})
	for _, path := range []string{"/default.htm", "/index.html", "/index.png"} {
		b.Apply(page("o", path, 200, 1, base))
	}

	want = map[string]Counts{
		"/":           pageCounts(1, 1),
		"/index.html": pageCounts(1, 1),
		"/index.png":  {HitBandwidth: 1, Hits: 1},
	}
	if got := counted(b, encKey(tagURL, "o", ym), Filter{}); !reflect.DeepEqual(got, want) {
		t.Errorf("paths with default.htm and index.png = %+v, want %+v", got, want)
	}
}

// A referrer counts without its query, and not at all when nothing else is left.
func TestReferrerQuery(t *testing.T) {
	var evs []logparse.Event

	for _, ref := range []string{"https://r.example/p?q=1", "https://r.example/p", "?q=1"} {
		ev := page("h", "/", 200, 1, base)
		ev.Referer = ref
		evs = append(evs, ev)
	}

	b := applied(evs...)

	want := map[string]Counts{"https://r.example/p": pageCounts(2, 2)}
	if got := counted(b, encKey(tagRef, "h", base.Format("200601")), Filter{}); !reflect.DeepEqual(got, want) {
		t.Errorf("referrers = %+v, want %+v", got, want)
	}
}

// A query starts only at "?" by default, and also at an added separator. A path loses its query before it is told a
// page, an index page or robots.txt.
func TestQuerySeparators(t *testing.T) {
	ym := base.Format("200601")
	ev := page("h", "/app;s=1", 200, 1, base)
	ev.Referer = "https://r.example/p;s=1"
	b := applied(ev)

	want := map[string]Counts{"/app;s=1": pageCounts(1, 1)}
	if got := counted(b, encKey(tagURL, "h", ym), Filter{}); !reflect.DeepEqual(got, want) {
		t.Errorf("paths by default = %+v, want %+v", got, want)
	}

	want = map[string]Counts{"https://r.example/p;s=1": pageCounts(1, 1)}
	if got := counted(b, encKey(tagRef, "h", ym), Filter{}); !reflect.DeepEqual(got, want) {
		t.Errorf("referrers by default = %+v, want %+v", got, want)
	}

	b = batchIn(time.UTC, Options{
		IndexPages:      []string{"index.html"},
		QuerySeparators: ";",
		ValidCodes:      []int{200},
		VisitTimeout:    DefaultVisitTimeout,
	})

	for _, path := range []string{"/app;s=1", "/index.html;s=1", "/logo.png;v=2", "/robots.txt;s=1"} {
		ev := page("o", path, 200, 1, base)
		ev.Referer = "https://r.example/p;s=1"
		b.Apply(ev)
	}

	all := Filter{Audience: AllAudiences}
	want = map[string]Counts{
		"/":           pageCounts(1, 1),
		"/app":        pageCounts(1, 1),
		"/logo.png":   {HitBandwidth: 1, Hits: 1},
		"/robots.txt": {HitBandwidth: 1, Hits: 1},
	}

	if got := counted(b, encKey(tagURL, "o", ym), all); !reflect.DeepEqual(got, want) {
		t.Errorf("paths with ; = %+v, want %+v", got, want)
	}

	if got := counted(b, encKey(tagCli, "o", ym), all)["bot"].Hits; got != 1 {
		t.Errorf("bot hits with ; = %d, want 1 for robots.txt", got)
	}

	want = map[string]Counts{"https://r.example/p": {HitBandwidth: 4, Hits: 4, PageBandwidth: 2, Pages: 2}}
	if got := counted(b, encKey(tagRef, "o", ym), all); !reflect.DeepEqual(got, want) {
		t.Errorf("referrers with ; = %+v, want %+v", got, want)
	}
}

// A day key gives its host and month, whether the host's length takes one byte of it or two. A key of another shape is
// refused.
func TestSplitDay(t *testing.T) {
	day := len(encKey(tagDay))
	date := base.Format("20060102")

	for _, host := range []string{"h", strings.Repeat("h", 200)} {
		name, month, ok := splitDay(timeKey(tagDay, host, date)[day:])
		if want := base.Format("2006-01"); !ok || name != host || month != want {
			t.Errorf("splitDay of %.10q... = %.10q..., %q, %v; want %q", host, name, month, ok, want)
		}
	}

	good := timeKey(tagDay, "h", date)[day:]

	for name, rest := range map[string][]byte{
		"cut length":     bytes.Repeat([]byte{0x80}, 8),
		"wrapped length": binary.AppendUvarint(nil, math.MaxUint64-7),
		"long date":      append(bytes.Clone(good), '0'),
	} {
		if _, _, ok := splitDay(rest); ok {
			t.Errorf("%s %q: split", name, rest)
		}
	}
}

// Bandwidth is capped at math.MaxInt64 within a batch.
func TestBandwidthCapped(t *testing.T) {
	ev := page("h", "/", 200, math.MaxInt64, base)

	got := counted(applied(ev, ev), encKey(tagDay, "h"), Filter{})[base.Format("20060102")]
	if got.HitBandwidth != math.MaxInt64 || got.PageBandwidth != math.MaxInt64 {
		t.Errorf("bandwidth = %d, %d of pages; want math.MaxInt64 for both", got.HitBandwidth, got.PageBandwidth)
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

	host := strings.Repeat("h", 2*maxValueLen)
	ev := page(host, ascii, 200, 1, base)
	ev.Referer = ascii
	b := applied(ev)
	short := host[:maxValueLen]

	if got := counted(b, encKey(tagDay, short), Filter{}); len(got) != 1 {
		t.Errorf("days of the clipped host = %+v, want one", got)
	}

	for _, tag := range []string{tagURL, tagRef} {
		if got := counted(b, encKey(tag, short, base.Format("200601")), Filter{}); got[ascii[:maxValueLen]].Hits != 1 {
			t.Errorf("values of %q = %d, want the clipped one", tag, len(got))
		}
	}
}

// A period is a year, a month or a day, returned without its dashes. Anything else is refused, and so is a filter with
// an unknown value.
func TestChecked(t *testing.T) {
	for period, want := range map[string]string{"2000": "2000", "2000-01": "200001", "2000-01-01": "20000101"} {
		if got, err := checked(period, Filter{}); got != want || err != nil {
			t.Errorf("checked(%q) = %q, %v; want %q", period, got, err, want)
		}
	}

	for _, period := range []string{
		"", "00", "200001", "2000/01", "20-00", "abcd", "2000-1", "2000-13", "2000-01-32", " 2000",
	} {
		if _, err := checked(period, Filter{}); !errors.Is(err, errBadPeriod) {
			t.Errorf("checked(%q): err = %v, want errBadPeriod", period, err)
		}
	}

	if _, err := checked("2000", Filter{Kind: FileKind + 1}); !errors.Is(err, errBadFilter) {
		t.Errorf("checked with an unknown kind: err = %v, want errBadFilter", err)
	}
}

// A year has its twelve months, and a month or a day only its own.
func TestMonths(t *testing.T) {
	var year []string
	for m := range 12 {
		year = append(year, base.AddDate(0, m, 0).Format("200601"))
	}

	for date, want := range map[string][]string{"2000": year, "200001": {"200001"}, "20000101": {"200001"}} {
		if got := months(date); !reflect.DeepEqual(got, want) {
			t.Errorf("months(%q) = %v, want %v", date, got, want)
		}
	}
}
