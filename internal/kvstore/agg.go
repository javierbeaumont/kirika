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
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/javierbeaumont/kirika/internal/logparse"
	"github.com/javierbeaumont/kirika/internal/uaclass"
	bolt "go.etcd.io/bbolt"
)

// The most bytes kept of a host or a dimension value from the log.
const maxValueLen = 1024

// Tags open every key in the agg bucket. A time series key is encKey(tag, host) + its date in the store's zone; a
// dimension key is encKey(tag, host, YYYYMM) + its value.
const (
	tagHour = "th" // YYYYMMDDHH
	tagDay  = "td" // YYYYMMDD
	tagURL  = "u"  // path
	tagStat = "s"  // HTTP status
	tagRef  = "r"  // referrer
	tagCli  = "c"  // client kind: desktop or mobile for a human, bot for a bot
)

var errBadPeriod = errors.New("kvstore: invalid period, want YYYY, YYYY-MM or YYYY-MM-DD")

// Options are the counting rules of a batch.
type Options struct {
	IndexPages      []string // file names of a directory's index page
	NotPages        []string // extensions never counted as pages, besides the image and download types
	QuerySeparators string   // characters besides "?" that start the query of a path or a referrer
	ValidCodes      []int    // the status codes of a correct request
}

// DefaultOptions returns the counting rules kirika uses unless told otherwise.
func DefaultOptions() Options {
	return Options{
		IndexPages: slices.Clone(defaultIndexPages),
		NotPages:   slices.Clone(defaultNotPages),
		ValidCodes: []int{http.StatusOK, http.StatusPartialContent, http.StatusNotModified},
	}
}

// Batch holds in memory what applied events add, until DB.Flush writes it in one transaction.
type Batch struct {
	d       map[string]tally
	index   []string // "/" and an index page name each
	loc     *time.Location
	notPage map[string]bool
	query   string // "?", which starts a query (RFC 3986, section 3.4), and the query separators
	valid   map[int]bool
}

// TimePoint is one bucket of a time series.
type TimePoint struct {
	At string // date in the store's zone, YYYYMMDD or YYYYMMDDHH
	Counts
}

// NewBatch returns an empty batch that counts by the rules of o, in the store's time zone.
func (db *DB) NewBatch(o Options) *Batch {
	b := &Batch{
		d:       map[string]tally{},
		loc:     db.loc,
		notPage: setOf(o.NotPages...),
		query:   "?" + o.QuerySeparators,
		valid:   map[int]bool{},
	}

	for _, name := range o.IndexPages {
		b.index = append(b.index, "/"+name)
	}

	for _, code := range o.ValidCodes {
		b.valid[code] = true
	}

	return b
}

// Apply counts one event in its class: in its hour, its day and each dimension of hostKey(ev.Host). It adds a hit, a
// page if the path is one, and its size as bandwidth. A 206 that does not start at byte 0 adds its size but no hit. A
// path and a referrer count without their query, and an index page under its directory. A missing status or referrer
// adds nothing there.
func (b *Batch) Apply(ev logparse.Event) {
	host := hostKey(ev.Host)
	path := cutQuery(ev.Path, b.query)

	client := uaclass.Classify(ev.UserAgent)
	if robotsTxt(path) {
		client = uaclass.Bot
	}

	cl := newClass(client == uaclass.Bot, b.group(ev.Status))

	c := Counts{HitBandwidth: ev.Size}
	if ev.Status != http.StatusPartialContent || ev.FirstPart {
		c.Hits = 1
	}

	if isPage(path, b.notPage) {
		c.Pages, c.PageBandwidth = c.Hits, ev.Size
		path = fold(path, b.index)
	}

	t := ev.Time.In(b.loc)
	b.add(timeKey(tagHour, host, t.Format("2006010215")), cl, c)
	b.add(timeKey(tagDay, host, t.Format("20060102")), cl, c)

	ym := t.Format("200601")
	b.add(dimKey(tagURL, host, ym, clip(path)), cl, c)
	b.add(dimKey(tagCli, host, ym, client), cl, c)

	if ev.Status != 0 {
		b.add(dimKey(tagStat, host, ym, strconv.Itoa(ev.Status)), cl, c)
	}

	if ref := cutQuery(ev.Referer, b.query); ref != "" {
		b.add(dimKey(tagRef, host, ym, clip(ref)), cl, c)
	}
}

// Returns the status group of a status code.
func (b *Batch) group(status int) int {
	switch {
	case b.valid[status]:
		return groupCorrect
	case status >= 100 && status < 400:
		return groupOther
	default:
		return groupError
	}
}

func (b *Batch) add(key []byte, cl class, c Counts) {
	b.d[string(key)] = b.d[string(key)].add(cl, c)
}

// Reports whether a path asks for robots.txt, which crawlers do and browsers do not. The rule follows AWStats:
// https://github.com/eldy/AWStats/blob/AWSTATS_8_0/wwwroot/cgi-bin/awstats.pl#L18526
func robotsTxt(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), "/robots.txt")
}

func timeKey(tag, host, date string) []byte {
	return append(encKey(tag, host), date...)
}

func dimKey(tag, host, ym, value string) []byte {
	return append(encKey(tag, host, ym), value...)
}

// Returns a host as every key holds it: lowercase and clipped, or "unknown" when empty.
func hostKey(host string) string {
	if host == "" {
		return "unknown"
	}

	return clip(strings.ToLower(host))
}

// Cuts s to at most maxValueLen bytes without splitting a character: a cut inside one moves back to its start, at most
// utf8.UTFMax-1 bytes. With no start there, s is not UTF-8 and is cut at maxValueLen.
func clip(s string) string {
	if len(s) <= maxValueLen {
		return s
	}

	for n := maxValueLen; n > maxValueLen-utf8.UTFMax; n-- {
		if utf8.RuneStart(s[n]) {
			return s[:n]
		}
	}

	return s[:maxValueLen]
}

// Flush adds the batch to the stored counters in one transaction and empties it. On error nothing is written and the
// batch is kept.
func (db *DB) Flush(b *Batch) error {
	if len(b.d) == 0 {
		return nil
	}

	err := db.b.Update(func(tx *bolt.Tx) error {
		agg := tx.Bucket(bktAgg)

		for k, t := range b.d {
			sum := t

			if v := agg.Get([]byte(k)); v != nil {
				stored, err := decodeTally(v)
				if err != nil {
					return err
				}

				// Only the stored counters change, so a failed flush leaves the batch as it was.
				for _, e := range t {
					stored = stored.add(e.class, e.Counts)
				}

				sum = stored
			}

			if err := agg.Put([]byte(k), encodeTally(sum)); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	b.d = map[string]tally{}

	return nil
}

// Checks a period in YYYY, YYYY-MM or YYYY-MM-DD and returns it without dashes, as key dates start.
func compact(period string) (string, error) {
	for _, l := range [...]struct{ in, out string }{
		{"2006", "2006"}, {"2006-01", "200601"}, {"2006-01-02", "20060102"},
	} {
		if t, err := time.Parse(l.in, period); err == nil && len(period) == len(l.in) {
			return t.Format(l.out), nil
		}
	}

	return "", fmt.Errorf("%w: %q", errBadPeriod, period)
}

// Calls fn with the rest and the counters of each agg key that starts with prefix and holds a class f counts. The rest
// is valid only inside fn.
func (db *DB) scan(prefix []byte, f Filter, fn func(rest []byte, c Counts)) error {
	return db.b.View(func(tx *bolt.Tx) error {
		cur := tx.Bucket(bktAgg).Cursor()
		for k, v := cur.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = cur.Next() {
			t, err := decodeTally(v)
			if err != nil {
				return err
			}

			if c, ok := f.sum(t); ok {
				fn(k[len(prefix):], c)
			}
		}

		return nil
	})
}

// Totals returns a host's counters over a period.
func (db *DB) Totals(host, period string, f Filter) (Counts, error) {
	date, err := checked(period, f)
	if err != nil {
		return Counts{}, err
	}

	var sum Counts

	err = db.scan(timeKey(tagDay, hostKey(host), date), f, func(_ []byte, c Counts) { sum.add(c) })

	return sum, err
}

// Series returns a host's tagHour or tagDay series over a period, in date order. A bucket with no class f counts is
// left out.
func (db *DB) Series(host, tag, period string, f Filter) ([]TimePoint, error) {
	date, err := checked(period, f)
	if err != nil {
		return nil, err
	}

	var out []TimePoint

	err = db.scan(timeKey(tag, hostKey(host), date), f, func(rest []byte, c Counts) {
		out = append(out, TimePoint{At: date + string(rest), Counts: c})
	})

	return out, err
}

// Dim returns a host's counters per value of a dimension tag over a period. Dimensions are kept per month, so a day
// reads its whole month. A value with no class f counts is left out.
func (db *DB) Dim(host, tag, period string, f Filter) (map[string]Counts, error) {
	date, err := checked(period, f)
	if err != nil {
		return nil, err
	}

	var months []string

	if len(date) == 4 {
		for m := 1; m <= 12; m++ {
			months = append(months, fmt.Sprintf("%s%02d", date, m))
		}
	} else {
		months = []string{date[:6]}
	}

	out := map[string]Counts{}

	for _, ym := range months {
		err := db.scan(encKey(tag, hostKey(host), ym), f, func(rest []byte, c Counts) {
			sum := out[string(rest)]
			sum.add(c)
			out[string(rest)] = sum
		})
		if err != nil {
			return nil, err
		}
	}

	return out, nil
}

// Returns the compact date of a period once both the period and the filter are valid.
func checked(period string, f Filter) (string, error) {
	if err := f.check(); err != nil {
		return "", err
	}

	return compact(period)
}
