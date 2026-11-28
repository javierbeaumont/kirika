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

package follow

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/javierbeaumont/kirika/internal/ingest"
)

// One read of a scripted log.
type step struct {
	err    error
	result ingest.Result
}

// A reader that gives its steps in turn and ends the run after the last one.
type script struct {
	cancel context.CancelFunc
	reads  int
	steps  []step
}

func (s *script) Read(context.Context) (ingest.Result, error) {
	current := s.steps[s.reads]

	s.reads++
	if s.reads == len(s.steps) {
		s.cancel()
	}

	return current.result, current.err
}

// Follows steps every interval, failing the test unless it reads each, and returns what it logged, from debug level up,
// and how many times it called onChange.
func follow(t *testing.T, interval time.Duration, steps ...step) (logged string, changes int) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var buf bytes.Buffer

	s := &script{cancel: cancel, steps: steps}
	Run(ctx, s, interval, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
		func() { changes++ })

	if s.reads != len(steps) {
		t.Errorf("%d reads, want %d", s.reads, len(steps))
	}

	return buf.String(), changes
}

// Unless told otherwise, kirika reads a followed log every 2 seconds.
func TestDefaultInterval(t *testing.T) {
	if DefaultInterval != 2*time.Second {
		t.Errorf("DefaultInterval = %v, want 2s", DefaultInterval)
	}
}

// onChange follows each read that counted a line, failed or not, and no other: a failed read keeps the chunks it
// flushed.
func TestRunChanges(t *testing.T) {
	_, changes := follow(t, time.Nanosecond,
		step{result: ingest.Result{Counted: 1}},
		step{result: ingest.Result{Blank: 1, Dropped: 1}},
		step{},
		step{err: errors.New("gone")},
		step{err: ingest.ErrUnreadable, result: ingest.Result{Malformed: 50}},
		step{err: errors.New("disk full"), result: ingest.Result{Counted: 4}},
		step{result: ingest.Result{Counted: 2}},
	)

	if changes != 3 {
		t.Errorf("onChange called %d times, want 3", changes)
	}
}

// The first read comes at once.
func TestRunNow(t *testing.T) {
	done := make(chan struct{})

	go func() {
		follow(t, time.Hour, step{result: ingest.Result{Counted: 1}})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("no read within a second of the start")
	}
}

// A run whose context has ended reads nothing, and a nil onChange is never called.
func TestRunEnded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	Run(ctx, &script{}, time.Nanosecond, slog.New(slog.DiscardHandler), nil)

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	Run(ctx, &script{cancel: cancel, steps: []step{{result: ingest.Result{Counted: 1}}}}, time.Nanosecond,
		slog.New(slog.DiscardHandler), nil)
}

// A reader whose read lasts until its context ends.
type stuck struct{ started chan struct{} }

func (s stuck) Read(ctx context.Context) (ingest.Result, error) {
	close(s.started)
	<-ctx.Done()

	return ingest.Result{Counted: 1}, ctx.Err()
}

// When the end of the context stops a read under way, the run returns at once, without a log or a call to onChange.
func TestRunStopped(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	s, done := stuck{started: make(chan struct{})}, make(chan struct{})

	var buf bytes.Buffer

	go func() {
		Run(ctx, s, time.Hour, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
			func() { t.Error("onChange called after a stopped read") })
		close(done)
	}()

	<-s.started
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run still running a second after its context ended")
	}

	if buf.Len() > 0 {
		t.Errorf("Run logged a stopped read:\n%s", buf.String())
	}
}

// A failed read is logged once until its error changes or a read succeeds again, which is told; its counts are logged
// as any read's.
func TestRunErrors(t *testing.T) {
	gone, bad := errors.New("log gone"), errors.New("format bad")
	logged, _ := follow(t, time.Nanosecond,
		step{err: gone}, step{err: gone}, step{err: bad, result: ingest.Result{Counted: 4, Malformed: 1}}, step{},
		step{}, step{err: gone})

	for text, want := range map[string]int{
		`msg="read failed" error="log gone"`:   2,
		`msg="read failed" error="format bad"`: 1,
		`msg="read again"`:                     1,
		`level=WARN msg="unreadable lines" counted=4 closed_year_pages=0 blank=0 not_access=0 dropped=0 malformed=1`: 1,
		"counted=": 1,
	} {
		if got := strings.Count(logged, text); got != want {
			t.Errorf("%d logs of %s, want %d:\n%s", got, text, want, logged)
		}
	}
}

// A read with an unreadable line or a page with a client of a closed year logs its counts as a warning, about the
// unreadable lines when it has both; any other that took lines, at debug level; and one that took none, nothing.
func TestRunReport(t *testing.T) {
	logged, _ := follow(t, time.Nanosecond,
		step{result: ingest.Result{Counted: 3, Malformed: 1}},
		step{result: ingest.Result{Binary: 1}},
		step{result: ingest.Result{TooLong: 1}},
		step{result: ingest.Result{BadDate: 1}},
		step{result: ingest.Result{Blank: 4, NotAccess: 5, Dropped: 6}},
		step{result: ingest.Result{Counted: 2}},
		step{result: ingest.Result{Counted: 2, ClosedYearPages: 1}},
		step{result: ingest.Result{Counted: 1, ClosedYearPages: 1, Malformed: 1}},
		step{},
	)

	for text, want := range map[string]int{
		`level=WARN msg="unreadable lines"`:                                        5,
		`counted=3 closed_year_pages=0 blank=0 not_access=0 dropped=0 malformed=1`: 1,
		`binary=1 too_long=0`:                                                      1,
		`too_long=1 bad_date=0`:                                                    1,
		`bad_date=1`:                                                               1,
		`level=DEBUG msg="lines read" counted=0 closed_year_pages=0 blank=4 not_access=5`: 1,
		`dropped=6 malformed=0`: 1,
		`level=DEBUG msg="lines read" counted=2 closed_year_pages=0`:                    1,
		`level=WARN msg="pages of a closed year" counted=2 closed_year_pages=1 blank=0`: 1,
		`level=WARN msg="unreadable lines" counted=1 closed_year_pages=1 blank=0`:       1,
		"\n": 8,
	} {
		if got := strings.Count(logged, text); got != want {
			t.Errorf("%d logs of %q, want %d:\n%s", got, text, want, logged)
		}
	}
}

// A run with a nil logger reads as any other, through reads it would log at each level.
func TestRunNilLog(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	reader := &script{cancel: cancel, steps: []step{
		{err: errors.New("gone")}, {result: ingest.Result{Malformed: 1}}, {result: ingest.Result{Counted: 1}},
	}}
	Run(ctx, reader, time.Nanosecond, nil, nil)

	if reader.reads != 3 {
		t.Errorf("%d reads, want 3", reader.reads)
	}
}

// Run panics on an interval that is not positive, naming it.
func TestRunInterval(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		func() {
			defer func() {
				want := fmt.Sprintf("follow: interval %v is not positive", interval)
				if got := recover(); got != want {
					t.Errorf("Run with interval %v: panic %v, want %q", interval, got, want)
				}
			}()

			Run(t.Context(), &script{}, interval, nil, nil)
		}()
	}
}
