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
	res ingest.Result
	err error
}

// A reader that gives its steps in turn and ends the run after the last one.
type script struct {
	cancel context.CancelFunc
	steps  []step
	reads  int
}

func (s *script) Read(context.Context) (ingest.Result, error) {
	st := s.steps[s.reads]

	s.reads++
	if s.reads == len(s.steps) {
		s.cancel()
	}

	return st.res, st.err
}

// Follows steps every interval, failing the test unless it reads each, and returns what it logged at debug level and
// how many times it called onChange.
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

// onChange follows each read that counted a line, and no other: a failed read wrote nothing, whatever it counted.
func TestRunChanges(t *testing.T) {
	_, changes := follow(t, time.Nanosecond,
		step{res: ingest.Result{Counted: 1}},
		step{res: ingest.Result{Blank: 1, Dropped: 1}},
		step{},
		step{err: errors.New("gone")},
		step{res: ingest.Result{Counted: 4, Malformed: 50}, err: ingest.ErrUnreadable},
		step{res: ingest.Result{Counted: 2}},
	)

	if changes != 2 {
		t.Errorf("onChange called %d times, want 2", changes)
	}
}

// The first read comes at once, not after an interval.
func TestRunNow(t *testing.T) {
	done := make(chan struct{})

	go func() {
		follow(t, time.Hour, step{res: ingest.Result{Counted: 1}})
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

	Run(ctx, &script{cancel: cancel, steps: []step{{res: ingest.Result{Counted: 1}}}}, time.Nanosecond,
		slog.New(slog.DiscardHandler), nil)
}

// A reader whose read lasts until its context ends.
type stuck struct{ started chan struct{} }

func (s stuck) Read(ctx context.Context) (ingest.Result, error) {
	close(s.started)
	<-ctx.Done()

	return ingest.Result{Counted: 1}, ctx.Err()
}

// The end of the context stops a read under way, and the run returns at once without a log or a call to onChange.
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

// A failed read is logged once until its error changes or a read succeeds again, which is told.
func TestRunErrors(t *testing.T) {
	gone, bad := errors.New("log gone"), errors.New("format bad")
	logged, _ := follow(t, time.Nanosecond,
		step{err: gone}, step{err: gone}, step{err: bad}, step{}, step{}, step{err: gone})

	for text, want := range map[string]int{
		`msg="read failed" error="log gone"`:   2,
		`msg="read failed" error="format bad"`: 1,
		`msg="read again"`:                     1,
	} {
		if got := strings.Count(logged, text); got != want {
			t.Errorf("%d logs of %s, want %d:\n%s", got, text, want, logged)
		}
	}
}

// A read with an unreadable line logs its counts as a warning, any other that took lines at debug level, and one that
// took none nothing.
func TestRunReport(t *testing.T) {
	logged, _ := follow(t, time.Nanosecond,
		step{res: ingest.Result{Counted: 3, Malformed: 1}},
		step{res: ingest.Result{Binary: 1}},
		step{res: ingest.Result{TooLong: 1}},
		step{res: ingest.Result{BadDate: 1}},
		step{res: ingest.Result{Blank: 4, NotAccess: 5, Dropped: 6}},
		step{},
	)

	for text, want := range map[string]int{
		`level=WARN msg="unreadable lines"`:                    4,
		`counted=3 blank=0 not_access=0 dropped=0 malformed=1`: 1,
		`binary=1 too_long=0`:                                  1,
		`too_long=1 bad_date=0`:                                1,
		`bad_date=1`:                                           1,
		`level=DEBUG msg="lines read" counted=0 blank=4 not_access=5 dropped=6`: 1,
		"\n": 5,
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
		{err: errors.New("gone")}, {res: ingest.Result{Malformed: 1}}, {res: ingest.Result{Counted: 1}},
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
