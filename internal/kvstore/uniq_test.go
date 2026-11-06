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
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/axiomhq/hyperloglog"
	"github.com/javierbeaumont/kirika/internal/logparse"
	bolt "go.etcd.io/bbolt"
)

// Returns the i-th of a range of distinct IPv4 addresses.
func ip(i int) string {
	return fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)
}

// Returns ev as made by client.
func from(client string, ev logparse.Event) logparse.Event {
	ev.ClientIP = client

	return ev
}

// Returns the page requests of host from the clients first to last-1 at t.
func visits(host string, first, last int, t time.Time) []logparse.Event {
	evs := make([]logparse.Event, 0, last-first)
	for i := first; i < last; i++ {
		evs = append(evs, from(ip(i), page(host, "/", 200, 1, t)))
	}

	return evs
}

func unique(t *testing.T, db *DB, host, period string, f Filter) uint64 {
	t.Helper()

	n, err := db.Unique(host, period, f)
	if err != nil {
		t.Fatalf("Unique(%q, %q, %+v): %v", host, period, f, err)
	}

	return n
}

// Reports whether got is within 5% of want, three times the sketch's standard error.
func near(got uint64, want int) bool {
	return math.Abs(float64(got)-float64(want)) <= 0.05*float64(want)
}

// Returns the encoding of a sketch of n distinct IPs at precision p.
func blob(t *testing.T, p uint8, n int) []byte {
	t.Helper()

	sk, err := hyperloglog.NewSketch(p, true)
	if err != nil {
		t.Fatalf("new sketch: %v", err)
	}

	for i := range n {
		sk.Insert([]byte(ip(i)))
	}

	b, err := sk.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	return b
}

// A client counts once, from its first page, under any case of the host. A request with no page or no client adds
// nothing, and hosts and months are counted apart.
func TestUnique(t *testing.T) {
	db := openStore(t)
	next := base.AddDate(0, 1, 0)

	evs := visits("h", 0, 1000, at(1, 0))
	evs = append(evs, visits("H", 0, 1000, at(2, 0))...)
	evs = append(evs, visits("other", 1000, 2000, at(1, 0))...)
	evs = append(evs, visits("h", 1000, 2000, next)...)
	evs = append(evs,
		page("no-client", "/", 200, 1, base),
		from(ip(0), page("files", "/logo.png", 200, 1, base)),
		from(ip(0), page("mixed", "/logo.png", 200, 1, base)),
		from(ip(0), page("mixed", "/", 200, 1, base)),
		from(ip(1), page("mixed", "/app.css", 200, 1, base)),
	)
	flush(t, db, evs...)

	for _, tc := range []struct {
		host, period string
		want         int
	}{
		{"h", "2000-01", 1000},
		{"H", "2000-01", 1000},
		{"no-client", "2000-01", 0},
		{"files", "2000-01", 0},
		{"mixed", "2000-01", 1},
		{"other", "2000-01", 1000},
		{"h", next.Format("2006-01"), 1000},
		{"h", "2000", 2000},
		{"h", next.AddDate(0, 1, 0).Format("2006-01"), 0},
		{"none", "2000", 0},
	} {
		if got := unique(t, db, tc.host, tc.period, Filter{}); !near(got, tc.want) {
			t.Errorf("Unique(%q, %q) = %d, want about %d", tc.host, tc.period, got, tc.want)
		}
	}
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

func TestClientKey(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.1":            "192.0.2.1",
		"::ffff:192.0.2.1":     "192.0.2.1",
		"2001:DB8::1":          "2001:db8::1",
		"2001:db8:0:0:0:0:0:1": "2001:db8::1",
		"fe80::1%eth0":         "fe80::1%eth0",
		"Client.Example":       "client.example",
		"192.0.2.1:80":         "192.0.2.1:80",
	} {
		if got := clientKey(in); got != want {
			t.Errorf("clientKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// A client counts once in any of its forms.
func TestUniqueClientForms(t *testing.T) {
	db := openStore(t)

	var evs []logparse.Event
	for _, c := range []string{
		"192.0.2.1", "::ffff:192.0.2.1", "2001:db8::1", "2001:DB8:0:0:0:0:0:1", "a.example", "A.Example",
	} {
		evs = append(evs, from(c, page("h", "/", 200, 1, base)))
	}

	flush(t, db, evs...)

	if got := unique(t, db, "h", "2000-01", Filter{}); got != 3 {
		t.Errorf("Unique = %d, want 3", got)
	}
}

// A day, an invalid period and an unknown filter value are errors.
func TestUniqueErrors(t *testing.T) {
	db := openStore(t)

	for _, tc := range []struct {
		period string
		f      Filter
		want   error
	}{
		{"2000-01-01", Filter{}, errDayUnique},
		{"2000/01", Filter{}, errBadPeriod},
		{"2000", Filter{Status: AllStatuses + 1}, errBadFilter},
	} {
		if _, err := db.Unique("h", tc.period, tc.f); !errors.Is(err, tc.want) {
			t.Errorf("Unique(%q, %+v): err = %v, want %v", tc.period, tc.f, err, tc.want)
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

// A sketch stays sparse while it holds few clients: ten take tens of bytes, not the 4 KB of every register.
func TestSketchSparse(t *testing.T) {
	db := openStore(t)
	flush(t, db, visits("h", 0, 10, base)...)

	key := uniqKey("h", base.Format("200601"), newClass(false, groupCorrect))

	err := db.b.View(func(tx *bolt.Tx) error {
		if n := len(tx.Bucket(bktUniq).Get(key)); n == 0 || n > 100 {
			t.Errorf("the sketch of ten clients takes %d bytes, want 1 to 100", n)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("view: %v", err)
	}
}

// A loaded sketch does not point into its stored bytes, which belong to bbolt and move when a later write remaps the
// file.
func TestLoadSketchCopies(t *testing.T) {
	dense := blob(t, hllPrecision, 20000)
	if dense[3] != 0 {
		t.Fatal("the sketch is sparse; only a dense one can point into its input")
	}

	sk, ok := loadSketch(dense)
	if !ok {
		t.Fatal("loadSketch refused a valid sketch")
	}

	before := sk.Estimate()

	for i := range dense {
		dense[i] = 0xff
	}

	if after := sk.Estimate(); after != before {
		t.Errorf("the estimate changed from %d to %d with the stored bytes", before, after)
	}
}

// An unreadable stored sketch counts as empty, and the next flush replaces it.
func TestUnreadableSketch(t *testing.T) {
	dense := blob(t, hllPrecision, 20000)
	key := uniqKey("h", base.Format("200601"), newClass(false, groupCorrect))

	for name, b := range map[string][]byte{
		"not a sketch":      []byte("not a sketch"),
		"other precision":   blob(t, 14, 100),
		"cut":               dense[:len(dense)-1],
		"trailing byte":     append(bytes.Clone(dense), 0),
		"unknown version":   append([]byte{9}, dense[1:]...),
		"unknown sparse":    append(append([]byte(nil), dense[:3]...), append([]byte{2}, dense[4:]...)...),
		"register too high": append(bytes.Clone(dense[:len(dense)-1]), 64),
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

// Each byte of a sparse and a dense sketch is altered, and whatever loadSketch accepts is merged: a fault inside the
// library would stop the process, past what a test or recover can catch.
func TestLoadSketchCorrupt(t *testing.T) {
	for _, b := range [][]byte{blob(t, hllPrecision, 100), blob(t, hllPrecision, 20000)} {
		for i := range b {
			for _, v := range []byte{0, 1, 0x7f, 0x80, 0xff} {
				c := bytes.Clone(b)
				c[i] = v

				if sk, ok := loadSketch(c); ok {
					acc := newSketch()
					if err := acc.Merge(sk); err != nil {
						t.Fatalf("byte %d = %#x: merge: %v", i, v, err)
					}

					acc.Estimate()
				}
			}
		}
	}
}
