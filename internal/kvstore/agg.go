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
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/axiomhq/hyperloglog"
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
	tagCli  = "c"  // client kind: desktop, mobile or unknown for a human, bot for a bot

	// Of these two, only Visits counts: the visits that began or ended on a page.
	tagEntry = "e" // path
	tagExit  = "x" // path
)

var (
	errBadKey    = errors.New("kvstore: corrupt key")
	errBadPeriod = errors.New("kvstore: invalid period, want YYYY, YYYY-MM or YYYY-MM-DD")
)

// DefaultVisitTimeout is the longest gap between two pages of one visit, unless told otherwise. It is AWStats'
// VISITTIMEOUT: https://github.com/eldy/AWStats/blob/AWSTATS_8_0/wwwroot/cgi-bin/awstats.pl#L62-L63
const DefaultVisitTimeout = time.Hour

// Options are the counting rules of a batch.
type Options struct {
	IndexPages      []string      // file names of a directory's index page
	NotPages        []string      // extensions never counted as pages, besides the image and download types
	QuerySeparators string        // characters besides "?" that start the query of a path or a referrer
	ValidCodes      []int         // the status codes of a correct request
	VisitTimeout    time.Duration // the longest gap between two pages of one visit
}

// DefaultOptions returns the counting rules kirika uses unless told otherwise.
func DefaultOptions() Options {
	return Options{
		IndexPages:   slices.Clone(defaultIndexPages),
		NotPages:     slices.Clone(defaultNotPages),
		ValidCodes:   []int{http.StatusOK, http.StatusPartialContent, http.StatusNotModified},
		VisitTimeout: DefaultVisitTimeout,
	}
}

// Batch holds in memory what applied events add and the log states set on it, until DB.Flush writes them in one
// transaction.
type Batch struct {
	d       map[string]tally
	events  []sessEvent // in log order
	index   []string    // "/" and an index page name each
	loc     *time.Location
	notPage map[string]bool
	query   string              // "?", which starts a query (RFC 3986, section 3.4), and the query separators
	state   map[string]LogState // by log path
	timeout time.Duration
	u       map[string]*hyperloglog.Sketch
	valid   map[int]bool
}

// Host is a host with data and the YYYY-MM months, in the store's zone, of its first and last days.
type Host struct {
	Name        string
	First, Last string
}

// TimePoint is one bucket of a time series.
type TimePoint struct {
	At string // date in the store's zone, YYYYMMDD or YYYYMMDDHH
	Counts
}

// NewBatch returns an empty batch that counts by the rules of o, in the store's time zone. It panics if o.VisitTimeout
// is not positive.
func (db *DB) NewBatch(o Options) *Batch {
	if o.VisitTimeout <= 0 {
		panic(fmt.Sprintf("kvstore: visit timeout %v is not positive", o.VisitTimeout))
	}

	b := &Batch{
		d:       map[string]tally{},
		loc:     db.loc,
		notPage: setOf(o.NotPages...),
		query:   "?" + o.QuerySeparators,
		state:   map[string]LogState{},
		timeout: o.VisitTimeout,
		u:       map[string]*hyperloglog.Sketch{},
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

// Apply counts one event in its class: in its hour, its day and each dimension of hostKey(event.Host). It adds a hit, a
// page if the path is one, and its size as bandwidth. A 206 that does not start at byte 0 adds its size but no hit. A
// path and a referrer count without their query, and an index page under its directory. A page also adds
// clientKey(event.ClientIP) to its month's unique visitors, and a correct one to the client's visits. A missing status,
// referrer or client adds nothing there. The client kind is uaclass.Bot when the path asks for robots.txt, else Unknown
// when the log carries no User-Agent.
func (b *Batch) Apply(event logparse.Event) {
	host := hostKey(event.Host)
	path := cutQuery(event.Path, b.query)

	clientKind := uaclass.Unknown
	if event.HasUserAgent {
		clientKind = uaclass.Classify(event.UserAgent)
	}

	if robotsTxt(path) {
		clientKind = uaclass.Bot
	}

	trafficClass := newClass(clientKind == uaclass.Bot, b.group(event.Status))

	counts := Counts{HitBandwidth: event.Size}
	if event.Status != http.StatusPartialContent || event.FirstPart {
		counts.Hits = 1
	}

	if isPage(path, b.notPage) {
		counts.Pages, counts.PageBandwidth = counts.Hits, event.Size
		path = fold(path, b.index)
	}

	localTime := event.Time.In(b.loc)
	b.add(timeKey(tagHour, host, localTime.Format("2006010215")), trafficClass, counts)
	b.add(timeKey(tagDay, host, localTime.Format("20060102")), trafficClass, counts)

	month := localTime.Format("200601")
	b.add(dimKey(tagURL, host, month, clip(path)), trafficClass, counts)
	b.add(dimKey(tagCli, host, month, clientKind), trafficClass, counts)

	if event.Status != 0 {
		b.add(dimKey(tagStat, host, month, strconv.Itoa(event.Status)), trafficClass, counts)
	}

	if referrer := cutQuery(event.Referer, b.query); referrer != "" {
		b.add(dimKey(tagRef, host, month, clip(referrer)), trafficClass, counts)
	}

	if event.ClientIP != "" && counts.Pages == 1 {
		visitor := clientKey(event.ClientIP)
		b.addUnique(host, month, trafficClass, visitor)

		if trafficClass.group() == groupCorrect {
			b.events = append(b.events, sessEvent{trafficClass, host, visitor, clip(path), localTime})
		}
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
	addTo(b.d, key, cl, c)
}

// Adds c to the counters of class cl under key.
func addTo(d map[string]tally, key []byte, cl class, c Counts) {
	d[string(key)] = d[string(key)].add(cl, c)
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

// Returns a client in one form: an IP in canonical text, a mapped IPv4 address as IPv4, and anything else in lowercase.
func clientKey(client string) string {
	if addr, err := netip.ParseAddr(client); err == nil {
		return addr.Unmap().String()
	}

	return strings.ToLower(client)
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

// Flush writes the batch in one transaction and empties it: its counters, sketches and sessions add to the stored ones,
// and its log states replace theirs. On error nothing is written and the batch is kept.
func (db *DB) Flush(b *Batch) error {
	if len(b.d) == 0 && len(b.state) == 0 {
		return nil
	}

	err := db.b.Update(func(tx *bolt.Tx) error {
		// The visits go to a copy, so a failed flush leaves the batch as it was.
		d := make(map[string]tally, len(b.d))
		for k, t := range b.d {
			d[k] = slices.Clone(t)
		}

		if err := sessions(tx.Bucket(bktSess), db.salt, b, d); err != nil {
			return err
		}

		agg := tx.Bucket(bktAgg)

		for k, t := range d {
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

		if err := writeState(tx.Bucket(bktState), b.state); err != nil {
			return err
		}

		return writeUnique(tx.Bucket(bktUniq), b.u)
	})
	if err != nil {
		return err
	}

	b.d = map[string]tally{}
	b.u = map[string]*hyperloglog.Sketch{}
	b.events = nil
	b.state = map[string]LogState{}

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

// Returns the YYYYMM months of a compact date: twelve for a year, else the date's own month.
func months(date string) []string {
	if len(date) > 4 {
		return []string{date[:6]}
	}

	out := make([]string, 0, 12)
	for m := 1; m <= 12; m++ {
		out = append(out, fmt.Sprintf("%s%02d", date, m))
	}

	return out
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

	out := map[string]Counts{}

	for _, ym := range months(date) {
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

// Hosts returns every host with data, in name order.
func (db *DB) Hosts() ([]Host, error) {
	var out []Host

	err := db.b.View(func(tx *bolt.Tx) error {
		day := encKey(tagDay)
		cur := tx.Bucket(bktAgg).Cursor()

		// A host's day keys are adjacent and in date order.
		for k, _ := cur.Seek(day); bytes.HasPrefix(k, day); k, _ = cur.Next() {
			name, month, ok := splitDay(k[len(day):])
			if !ok {
				return fmt.Errorf("%w: %q", errBadKey, k)
			}

			if n := len(out); n > 0 && out[n-1].Name == name {
				out[n-1].Last = month
			} else {
				out = append(out, Host{Name: name, First: month, Last: month})
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	slices.SortFunc(out, func(a, b Host) int { return strings.Compare(a.Name, b.Name) })

	return out, nil
}

// Returns the host and the YYYY-MM month of a day key from what follows its encKey(tagDay). ok is false for a key of
// another shape.
func splitDay(rest []byte) (host, month string, ok bool) {
	n, w := binary.Uvarint(rest)
	if w <= 0 || len(rest) < w+8 || n != uint64(len(rest)-w-8) {
		return "", "", false
	}

	date := rest[len(rest)-8:]

	return string(rest[w : len(rest)-8]), string(date[:4]) + "-" + string(date[4:6]), true
}
