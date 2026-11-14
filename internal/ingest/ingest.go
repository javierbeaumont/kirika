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

// Package ingest reads access logs into a store. A read goes on after the last line the previous one took, counts its
// lines in one batch and writes them, with where it stopped, in one transaction.
package ingest

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/javierbeaumont/kirika/internal/kvstore"
	"github.com/javierbeaumont/kirika/internal/logparse"
)

// How far ahead of a read a line may be dated, for a clock that runs a little fast.
const ahead = 24 * time.Hour

// The unreadable lines in a row that stop a read: a wrong log format makes every line one.
const maxRun = 50

// ErrUnreadable is the error of a read stopped by maxRun unreadable lines in a row.
var ErrUnreadable = errors.New("ingest: too many unreadable lines in a row")

// Options are the rules of a read.
type Options struct {
	Count       kvstore.Options  // the counting rules of the store's batch
	DefaultHost string           // the host of a line whose log names none, put in the form logparse.VHost returns
	Log         *slog.Logger     // where each line not counted is told, at debug level; nil tells nothing
	Methods     []string         // the methods whose lines count; a line with another is dropped
	Now         func() time.Time // the clock of the 24 hours a line may be ahead; nil is time.Now
}

// DefaultOptions returns the rules kirika reads with unless told otherwise.
func DefaultOptions() Options {
	return Options{Count: kvstore.DefaultOptions(), Methods: DefaultMethods()}
}

// DefaultMethods returns the methods counted unless told otherwise: HTTP's (RFC 9110) but TRACE and CONNECT, which view
// no page, PATCH (RFC 5789) and WebDAV's (RFC 4918).
func DefaultMethods() []string {
	return []string{
		"COPY", "DELETE", "GET", "HEAD", "LOCK", "MKCOL", "MOVE", "OPTIONS", "PATCH", "POST", "PROPFIND", "PROPPATCH",
		"PUT", "UNLOCK",
	}
}

// Result counts the lines of a read by what became of them.
type Result struct {
	Counted   int // in the store
	Blank     int // empty or spaces only
	NotAccess int // a message that is not an access, which Caddy writes in its log too
	Dropped   int // a method out of Options.Methods
	Malformed int // unreadable: the parser refused it
	Binary    int // unreadable: it starts with a NUL byte
	TooLong   int // unreadable: longer than 1 MiB
	BadDate   int // unreadable: dated more than 24 hours after the read, or before the year 1000
}

// Unreadable returns the number of unreadable lines.
func (res Result) Unreadable() int {
	return res.Malformed + res.Binary + res.TooLong + res.BadDate
}

// Reader reads one log into a store, a read at a time.
type Reader struct {
	count   kvstore.Options
	db      *kvstore.DB
	host    string
	log     *slog.Logger
	methods map[string]bool
	now     func() time.Time
	parse   logparse.Parser
	path    string // absolute, the key of the log's state
	run     int    // unreadable lines in a row at the end of the last read that wrote
}

// New returns a reader of the log at path that parses its lines with parse and counts them into db by the rules of o.
// It refuses a visit timeout that is not positive, a nil parser, an empty method list and a method that is empty or not
// in upper case.
func New(db *kvstore.DB, path string, parse logparse.Parser, o Options) (*Reader, error) {
	if err := o.check(parse); err != nil {
		return nil, err
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	r := &Reader{
		count:   o.Count,
		db:      db,
		host:    logparse.VHost(o.DefaultHost),
		log:     o.Log,
		methods: map[string]bool{},
		now:     o.Now,
		parse:   parse,
		path:    abs,
	}

	for _, m := range o.Methods {
		r.methods[m] = true
	}

	if r.log == nil {
		r.log = slog.New(slog.DiscardHandler)
	}

	if r.now == nil {
		r.now = time.Now
	}

	return r, nil
}

// Returns why New refuses o or parse, if it does.
func (o Options) check(parse logparse.Parser) error {
	switch {
	case o.Count.VisitTimeout <= 0:
		return fmt.Errorf("ingest: visit timeout %v is not positive", o.Count.VisitTimeout)
	case parse == nil:
		return errors.New("ingest: no parser")
	case len(o.Methods) == 0:
		return errors.New("ingest: no method to count")
	}

	for _, m := range o.Methods {
		if m == "" || m != strings.ToUpper(m) {
			return fmt.Errorf("ingest: method %q is empty or not in upper case", m)
		}
	}

	return nil
}

// Read counts the lines written to the log since the last read and stores where it stopped, all in one transaction. It
// goes on after the last line read when that line is still at its offset, and else reads the log from its start: the
// path holds a new one. A last line with no newline yet waits for the next read. A read with no new line writes
// nothing. maxRun unreadable lines in a row, counted across reads, stop it with ErrUnreadable. A failed read writes
// nothing, though its Result counts the lines it read before the error.
func (r *Reader) Read() (Result, error) {
	var res Result

	s, ok, err := r.db.State(r.path)
	if err != nil {
		return res, err
	}

	f, err := os.Open(r.path)
	if err != nil {
		return res, err
	}
	defer func() { _ = f.Close() }() // read only: a failed close loses nothing

	br, off, num, err := resume(f, s, ok)
	if err != nil {
		return res, err
	}

	b := r.db.NewBatch(r.count)
	limit := r.now().Add(ahead)
	run := r.run

	var (
		last line
		read bool // a line at least
	)

	for {
		l, n, more, err := next(br, off)
		if err != nil {
			return res, err
		}

		if !more {
			break
		}

		off += n
		num++
		last, read = l, true

		ev, judged, why := judge(l, r.parse, r.methods, r.host, limit)
		res.add(judged)

		switch {
		case judged == counted:
			b.Apply(ev)

			run = 0
		case judged == dropped:
			r.tell("line dropped", l, num, judged, "method", ev.Method)

			run = 0
		case judged.unreadable():
			r.tell("line unreadable", l, num, judged, "error", why)

			run++
		default:
			r.tell("line skipped", l, num, judged)
		}

		if run >= maxRun {
			return res, fmt.Errorf("%w: %d, the last line %d; is the log format right?", ErrUnreadable, run, num)
		}
	}

	if !read {
		return res, nil
	}

	b.SetState(r.path, kvstore.LogState{Line: num, Offset: last.start, Sum: last.sum})

	if err := r.db.Flush(b); err != nil {
		return res, err
	}

	r.run = run

	return res, nil
}

// Tells at debug level what became of line number num, which was not counted, never its content: it holds a client
// address.
func (r *Reader) tell(msg string, l line, num int64, f fate, attrs ...any) {
	r.log.Debug(msg, append([]any{"path", r.path, "line", num, "offset", l.start, "reason", f.String()}, attrs...)...)
}

// Places a reader of f after the line s names, when ok and that line is still there; else at the start of f, which
// holds a new log. It also returns the reader's offset and the number of the line before it.
func resume(f *os.File, s kvstore.LogState, ok bool) (*bufio.Reader, int64, int64, error) {
	if ok {
		if _, err := f.Seek(s.Offset, io.SeekStart); err != nil {
			return nil, 0, 0, err
		}

		br := bufio.NewReader(f)

		l, n, more, err := next(br, s.Offset)
		if err != nil {
			return nil, 0, 0, err
		}

		if more && l.sum == s.Sum {
			return br, s.Offset + n, s.Line, nil
		}
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, 0, 0, err
	}

	return bufio.NewReader(f), 0, 0, nil
}

// What becomes of a line.
type fate int

const (
	counted fate = iota
	blank
	notAccess
	dropped
	malformed // the first unreadable one
	binary
	tooLong
	badDate
)

// Reports whether a line with fate f is unreadable.
func (f fate) unreadable() bool { return f >= malformed }

func (f fate) String() string {
	return [...]string{
		counted:   "counted",
		blank:     "blank",
		notAccess: "not an access",
		dropped:   "method not counted",
		malformed: "malformed",
		binary:    "binary",
		tooLong:   "longer than 1 MiB",
		badDate:   "dated more than 24 hours ahead or before the year 1000",
	}[f]
}

// Adds a line with fate f to its counter.
func (res *Result) add(f fate) {
	switch f {
	case counted:
		res.Counted++
	case blank:
		res.Blank++
	case notAccess:
		res.NotAccess++
	case dropped:
		res.Dropped++
	case malformed:
		res.Malformed++
	case binary:
		res.Binary++
	case tooLong:
		res.TooLong++
	case badDate:
		res.BadDate++
	}
}

// Decides the fate of a line and returns its event, with host when its log names none. why is the parser's error for a
// malformed line.
func judge(l line, parse logparse.Parser, methods map[string]bool, host string, limit time.Time) (
	ev logparse.Event, f fate, why error,
) {
	switch {
	case l.long:
		return ev, tooLong, nil
	case len(bytes.TrimSpace(l.text)) == 0:
		return ev, blank, nil
	case l.text[0] == 0:
		return ev, binary, nil
	}

	ev, err := parse(l.text)

	switch {
	case errors.Is(err, logparse.ErrNotAccessLog):
		return ev, notAccess, nil
	case err != nil:
		return ev, malformed, err
	case !methods[ev.Method]:
		return ev, dropped, nil
	case ev.Time.Year() < 1000 || ev.Time.After(limit):
		return ev, badDate, nil
	}

	if ev.Host == "" {
		ev.Host = host
	}

	return ev, counted, nil
}
