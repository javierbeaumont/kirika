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

// Package ingest reads access logs into a store. A read goes on after the last line stored and counts its lines in
// batches, each written in one transaction with the state of its last line.
package ingest

import (
	"bufio"
	"bytes"
	"context"
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

// The lines between two flushes of a read, as a batch grows with its lines: a read of 1,500,000 lines of 500,000
// clients peaked at 43 MB of heap, where one batch took 617 MB.
const chunk = 50_000

// ErrUnreadable is the error of the first read of a path when it finds unreadable lines and no readable one, as with a
// wrong log format.
var ErrUnreadable = errors.New("ingest: no readable line in the first read of a log")

// Options are the rules of a read.
type Options struct {
	Count       kvstore.Options  // the counting rules of the store's batch
	DefaultHost string           // the host of a line whose log names none, put in the form logparse.VHost returns
	Log         *slog.Logger     // where reads warn, and tell each line not counted at debug level; nil tells nothing
	Methods     []string         // the methods whose lines count; a line with another is dropped
	NoUserAgent bool             // the log carries no User-Agent, even where a line seems to hold an empty one
	Now         func() time.Time // the clock of the 24 hours a line may be ahead; nil is time.Now
	Rotated     []string         // globs of the log's rotated files from its directory; nil is logrotate's and Caddy's
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
	Counted         int // in the store
	ClosedYearPages int // the counted pages with a client of a year closed before their flush: no unique visitor
	Blank           int // empty or spaces only
	NotAccess       int // a message that is not an access, which Caddy writes in its log too
	Dropped         int // a method out of Options.Methods
	Malformed       int // unreadable: the parser refused it
	Binary          int // unreadable: it starts with a NUL byte
	TooLong         int // unreadable: longer than 1 MiB
	BadDate         int // unreadable: dated over 24 hours ahead, or out of years 1000-9999 in the store's zone
}

// Unreadable returns the number of unreadable lines.
func (res Result) Unreadable() int {
	return res.Malformed + res.Binary + res.TooLong + res.BadDate
}

// Reader reads one log into a store, a read at a time. It keeps the log open between reads, until Close.
type Reader struct {
	chunk   int // chunk outside a test
	count   kvstore.Options
	db      *kvstore.DB
	file    *os.File // the log kept open, nil when none
	host    string
	log     *slog.Logger
	methods map[string]bool
	now     func() time.Time
	parse   logparse.Parser
	path    string   // absolute, the key of the log's state
	rotated []string // absolute globs
	warned  bool     // that the log has no access line yet
}

// New returns a reader of the log at path that parses its lines with parse and counts them into db by the rules of
// options. It refuses counting rules that kvstore.Options.Check refuses, a nil parser, an empty method list, a method
// that is empty or not in upper case and a malformed glob of rotated files.
func New(db *kvstore.DB, path string, parse logparse.Parser, options Options) (*Reader, error) {
	if err := options.check(parse); err != nil {
		return nil, err
	}

	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	reader := &Reader{
		chunk:   chunk,
		count:   options.Count,
		db:      db,
		host:    logparse.VHost(options.DefaultHost),
		log:     options.Log,
		methods: map[string]bool{},
		now:     options.Now,
		parse:   parse,
		path:    absolute,
	}

	for _, method := range options.Methods {
		reader.methods[method] = true
	}

	rotated := options.Rotated
	if rotated == nil {
		rotated = defaultRotated(filepath.Base(absolute))
	}

	for _, pattern := range rotated {
		if !filepath.IsAbs(pattern) {
			pattern = filepath.Join(escapeGlob(filepath.Dir(absolute)), pattern)
		}

		reader.rotated = append(reader.rotated, pattern)
	}

	if options.NoUserAgent {
		reader.parse = withoutUserAgent(parse)
	}

	if reader.log == nil {
		reader.log = slog.New(slog.DiscardHandler)
	}

	if reader.now == nil {
		reader.now = time.Now
	}

	return reader, nil
}

// Returns parse with each event read as one whose log carries no User-Agent.
func withoutUserAgent(parse logparse.Parser) logparse.Parser {
	return func(line []byte) (logparse.Event, error) {
		event, err := parse(line)
		event.HasUserAgent = false

		return event, err
	}
}

// Returns why New refuses o or parse, if it does.
func (o Options) check(parse logparse.Parser) error {
	if err := o.Count.Check(); err != nil {
		return err
	}

	switch {
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

	for _, pattern := range o.Rotated {
		if _, err := filepath.Match(pattern, ""); err != nil {
			return fmt.Errorf("ingest: rotated files %q: %w", pattern, err)
		}
	}

	return nil
}

// Read counts the lines written to the log since the last flush. It flushes in chunks of lines and at its end, each
// flush in one transaction with the state of its last line. It goes on after the last line flushed when that line is
// still at its offset, and else reads the log from its start: the path holds a new one. When the path names another
// file than the one the reader keeps open, as after a rotation by rename, it first reads what the old file gained, then
// the new one from its start, and keeps the new one; one with no whole line yet gets the state of no line read. When
// the reader keeps no file, as a new one, and the path's file does not hold the state's line, it first reads the rest
// of the rotated file that does, then each newer one, oldest first, as Options.Rotated finds them. A state of no line
// read may name the last line of the log before. It warns if no rotated file holds a line of the log read last. When
// the path names no file and the one kept open has no name left, it reads what that one gained and releases it. A last
// line with no newline yet waits for the next read. A read with no new line writes nothing, unless it moves to a new
// log or releases a deleted one; either records the state of no line read. The first read of a path, which has no state
// yet, writes nothing unless it finds a readable line, counted or dropped, and fails with ErrUnreadable if it finds an
// unreadable one instead. If it finds only lines of neither kind, it warns once per reader. Any other read skips
// unreadable lines. Once ctx ends, a read fails with ctx's error before its next line. A failed read keeps what it
// flushed and the file of its last flush, else the old one; its Result counts the lines it read before the error.
func (r *Reader) Read(ctx context.Context) (Result, error) {
	var progress scan

	state, hasState, err := r.db.State(r.path)
	if err != nil {
		return progress.result, err
	}

	file, err := r.open()

	gone := errors.Is(err, os.ErrNotExist) && r.file != nil && deleted(r.file)
	if gone {
		file, err = r.file, nil
	}

	if err != nil {
		return progress.result, err
	}

	err = r.readAll(ctx, file, state, hasState, &progress)
	if err == nil && gone {
		moveTo(nil, lastOr(progress.last, state), &progress)
	}

	switch {
	case err != nil:
	case !hasState && !progress.readable:
		err = progress.refused

		if err == nil && progress.pending > 0 && !r.warned {
			r.log.Warn("no access line yet, so each read starts the log over", "path", r.path)

			r.warned = true
		}
	case progress.pending > 0 || progress.moved:
		err = r.flush(&progress)
	}

	// The logs are open read only, so a failed close loses nothing.
	switch {
	case err != nil:
		if file != r.file {
			_ = file.Close()
		}
	case gone:
		_ = r.Close()
	case file != r.file:
		_ = r.Close()
		r.file = file
	}

	return progress.result, err
}

// Close releases the log the reader keeps open. A later read opens it again.
func (r *Reader) Close() error {
	if r.file == nil {
		return nil
	}

	err := r.file.Close()
	r.file = nil

	return err
}

// Returns the file the path names: r.file while the path still names it, else a new one opened.
func (r *Reader) open() (*os.File, error) {
	if r.file != nil {
		named, err := os.Stat(r.path)
		if err != nil {
			return nil, err
		}

		last, err := r.file.Stat()
		if err != nil {
			return nil, err
		}

		if os.SameFile(named, last) {
			return r.file, nil
		}
	}

	return os.Open(r.path)
}

// What a read found, across the files it read.
type scan struct {
	batch    *kvstore.Batch
	file     *os.File         // last's file, nil for a rotated file's
	last     kvstore.LogState // the last line read, or none in a log moved to
	moved    bool             // the read moved to a new log, or released a deleted one
	pending  int              // the lines read since the last flush
	readable bool             // a line counted or dropped
	refused  error            // ErrUnreadable, naming the first unreadable line
	result   Result
	stated   bool // the path had a state before the read
}

// Flushes progress's batch with the state of its last line and keeps progress.file open in place of r.file.
func (r *Reader) flush(progress *scan) error {
	progress.batch.SetState(r.path, progress.last)

	closedYearPages, err := r.db.Flush(progress.batch)
	if err != nil {
		return err
	}

	progress.pending = 0
	progress.result.ClosedYearPages += closedYearPages

	if progress.file != r.file {
		_ = r.Close() // read only: a failed close loses nothing
		r.file = progress.file
	}

	return nil
}

// Reads file into progress as readFile does. When r.file is another file, it reads r.file first, then file from its
// start. When the reader keeps no file and file does not hold state's line, it first reads the rotated files after that
// line, as readRotated does, then file from its start.
func (r *Reader) readAll(ctx context.Context, file *os.File, state kvstore.LogState, hasState bool,
	progress *scan,
) error {
	progress.batch, progress.stated = r.db.NewBatch(r.count), hasState
	limit := r.now().Add(ahead)

	if r.file != nil && file != r.file {
		if err := r.readFile(ctx, r.file, state, hasState, limit, progress); err != nil {
			return err
		}

		moveTo(file, lastOr(progress.last, state), progress)

		hasState = false
	}

	lines, offset, lineNum, err := resume(file, state, hasState)
	if err != nil {
		return err
	}

	if r.file == nil && hasState && lineNum == 0 && state.Offset >= 0 {
		found, err := r.readRotated(ctx, file, state, limit, progress)
		if err != nil {
			return err
		}

		before := noLineBefore
		if found {
			before = lastOr(progress.last, state)
		}

		moveTo(file, before, progress)
	}

	return r.readLines(ctx, file, "", lines, offset, lineNum, limit, progress)
}

// The state of no line read with no line before it to look for.
var noLineBefore = kvstore.LogState{Offset: -1}

// Starts progress on file, a log with no line read yet, which the next read takes from its start until a line of it is
// flushed; nil is the log to come after a deleted one. Its state of no line read keeps the offset and checksum of
// before, the last line read of the log before, so that a new reader can find that line among the rotated files once
// the log after is rotated in its turn.
func moveTo(file *os.File, before kvstore.LogState, progress *scan) {
	progress.file, progress.last, progress.moved = file, kvstore.LogState{Offset: before.Offset, Sum: before.Sum}, true
}

// Returns last when it names a line read, else state.
func lastOr(last, state kvstore.LogState) kvstore.LogState {
	if last.Line > 0 {
		return last
	}

	return state
}

// Reads file into progress, after state's line when hasState and that line is still there, else from its start.
func (r *Reader) readFile(ctx context.Context, file *os.File, state kvstore.LogState, hasState bool, limit time.Time,
	progress *scan,
) error {
	lines, offset, lineNum, err := resume(file, state, hasState)
	if err != nil {
		return err
	}

	return r.readLines(ctx, file, "", lines, offset, lineNum, limit, progress)
}

// Reads lines into progress, from offset, after line number lineNum. They come from file, which a flush keeps open, or
// from the rotated file named rotated, when file is nil. Lines dated after limit are unreadable.
func (r *Reader) readLines(ctx context.Context, file *os.File, rotated string, lines *bufio.Reader, offset,
	lineNum int64, limit time.Time, progress *scan,
) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		logLine, size, more, err := next(lines, offset)
		if err != nil {
			return err
		}

		if !more {
			return nil
		}

		offset += size
		lineNum++
		progress.file, progress.last = file, kvstore.LogState{Line: lineNum, Offset: logLine.start, Sum: logLine.sum}
		progress.pending++

		event, judged, why := judge(logLine, r.parse, r.methods, r.host, limit, r.db.Location())
		progress.result.add(judged)

		switch {
		case judged == counted:
			progress.batch.Apply(event)

			progress.readable = true
		case judged == dropped:
			r.tell("line dropped", rotated, logLine, lineNum, judged, "method", event.Method)

			progress.readable = true
		case judged.unreadable():
			r.tell("line unreadable", rotated, logLine, lineNum, judged, "error", why)

			if progress.refused == nil {
				progress.refused = unreadable(lineNum, judged, why)
			}
		default:
			r.tell("line skipped", rotated, logLine, lineNum, judged)
		}

		if progress.pending >= r.chunk && (progress.stated || progress.readable) {
			if err := r.flush(progress); err != nil {
				return err
			}
		}
	}
}

// Wraps ErrUnreadable with line number num, its fate f and the parser's error why, if any.
func unreadable(num int64, f fate, why error) error {
	if why != nil {
		return fmt.Errorf("%w; line %d is %v: %w", ErrUnreadable, num, f, why)
	}

	return fmt.Errorf("%w; line %d is %v", ErrUnreadable, num, f)
}

// Tells at debug level what became of line number lineNum, which was not counted, never its content: it holds a client
// address. rotated names the rotated file it is in, if any.
func (r *Reader) tell(msg, rotated string, logLine line, lineNum int64, judged fate, attrs ...any) {
	if rotated != "" {
		attrs = append(attrs, "file", rotated)
	}

	r.log.Debug(msg, append([]any{"path", r.path, "line", lineNum, "offset", logLine.start, "reason", judged.String()},
		attrs...)...)
}

// Places a reader of f after the line s names, when ok and s names a line that is still there; else at the start of f,
// which holds a new log. It also returns the reader's offset and the number of the line before it.
func resume(f *os.File, s kvstore.LogState, ok bool) (*bufio.Reader, int64, int64, error) {
	if ok && s.Line > 0 {
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
		badDate:   "dated more than 24 hours ahead or out of years 1000-9999",
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
// malformed line. A line whose method counts is unreadable when dated after limit or out of the years 1000 to 9999 in
// zone.
func judge(logLine line, parse logparse.Parser, methods map[string]bool, host string, limit time.Time,
	zone *time.Location,
) (event logparse.Event, judged fate, why error) {
	switch {
	case logLine.long:
		return event, tooLong, nil
	case len(bytes.TrimSpace(logLine.text)) == 0:
		return event, blank, nil
	case logLine.text[0] == 0:
		return event, binary, nil
	}

	event, err := parse(logLine.text)

	switch {
	case errors.Is(err, logparse.ErrNotAccessLog):
		return event, notAccess, nil
	case err != nil:
		return event, malformed, err
	case !methods[event.Method]:
		return event, dropped, nil
	}

	if year := event.Time.In(zone).Year(); year < 1000 || year > 9999 || event.Time.After(limit) {
		return event, badDate, nil
	}

	if event.Host == "" {
		event.Host = host
	}

	return event, counted, nil
}
