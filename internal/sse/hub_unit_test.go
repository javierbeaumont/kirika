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

package sse

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A response writer that hands each flushed chunk to its channel and keeps its write deadline: now, at its last flush,
// and the one its last deadline replaced. Setting a deadline, writing, flushing or clearing the deadline fails once
// told to.
type stream struct {
	header        http.Header
	buf           bytes.Buffer
	chunks        chan string
	deadline      atomic.Int64 // in Unix nanoseconds, 0 when cleared
	flushDeadline atomic.Int64
	priorDeadline atomic.Int64
	failDeadline  atomic.Bool
	failWrite     atomic.Bool
	failFlush     atomic.Bool
	failClear     atomic.Bool
}

func newStream() *stream {
	return &stream{header: http.Header{}, chunks: make(chan string, 16)}
}

func (s *stream) Header() http.Header { return s.header }

func (s *stream) WriteHeader(int) {}

func (s *stream) SetWriteDeadline(deadline time.Time) error {
	switch {
	case deadline.IsZero() && s.failClear.Load():
		return errors.New("clear failed")
	case deadline.IsZero():
		s.deadline.Store(0)
	case s.failDeadline.Load():
		return errors.New("deadline failed")
	default:
		s.priorDeadline.Store(s.deadline.Swap(deadline.UnixNano()))
	}

	return nil
}

func (s *stream) Write(p []byte) (int, error) {
	if s.failWrite.Load() {
		return 0, errors.New("write failed")
	}

	return s.buf.Write(p)
}

func (s *stream) FlushError() error {
	if s.failFlush.Load() {
		return errors.New("flush failed")
	}

	s.flushDeadline.Store(s.deadline.Load())

	s.chunks <- s.buf.String()

	s.buf.Reset()

	return nil
}

// Returns the next chunk s flushes, failing the test after a second without one.
func next(t *testing.T, s *stream) string {
	t.Helper()

	select {
	case c := <-s.chunks:
		return c
	case <-time.After(time.Second):
		t.Fatal("no chunk within a second")
	}

	return ""
}

// Serves a stream from h to w in the background: done closes when it returns, end cancels the request.
func serve(h *Hub, w http.ResponseWriter) (done chan struct{}, end func()) {
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequest(http.MethodGet, "/api/stream", nil).WithContext(ctx)
	done = make(chan struct{})

	go func() {
		h.ServeHTTP(w, r)
		close(done)
	}()

	return done, cancel
}

// Fails the test unless h refuses a stream with a 503.
func refused(t *testing.T, h *Hub, when string) {
	t.Helper()

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/stream", nil))

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("%s: status %d, want 503", when, w.Code)
	}
}

// Returns the number of open streams of h.
func open(h *Hub) int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return len(h.subs)
}

// Fails the test unless done closes within a second.
func wait(t *testing.T, done chan struct{}, what string) {
	t.Helper()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("%s: the stream still runs after a second", what)
	}
}

func TestDefaultOptions(t *testing.T) {
	if got, want := DefaultOptions(), (Options{Keepalive: 25 * time.Second, MaxStreams: 16}); got != want {
		t.Errorf("%+v, want %+v", got, want)
	}
}

// NewHub panics on a keepalive or a stream limit that is not positive.
func TestNewHubLimits(t *testing.T) {
	for _, o := range []Options{
		{Keepalive: 0, MaxStreams: 1},
		{Keepalive: -time.Second, MaxStreams: 1},
		{Keepalive: time.Second, MaxStreams: 0},
		{Keepalive: time.Second, MaxStreams: -1},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("NewHub with %+v did not panic", o)
				}
			}()

			NewHub(o)
		}()
	}
}

// A stream gets one signal for any broadcasts it has not taken yet, and none once it is closed.
func TestBroadcast(t *testing.T) {
	h := NewHub(DefaultOptions())
	ch := h.subscribe()

	h.Broadcast()
	h.Broadcast()

	for _, want := range []bool{true, false} {
		select {
		case <-ch:
			if !want {
				t.Error("two broadcasts gave two signals")
			}
		default:
			if want {
				t.Error("no signal after two broadcasts")
			}
		}
	}

	h.unsubscribe(ch)
	h.Broadcast()

	select {
	case <-ch:
		t.Error("a closed stream got a signal")
	default:
	}

	if n := open(h); n != 0 {
		t.Errorf("%d streams open after the last closed", n)
	}
}

// A stream sends its headers and an update at once, and another after a broadcast, each under a write deadline it
// clears once flushed. It ends when its client leaves, with a deadline for the server's last write. Each deadline is
// the hub's write timeout away, writeTimeout in a new hub.
func TestServe(t *testing.T) {
	h := NewHub(Options{Keepalive: time.Hour, MaxStreams: 1})
	if h.writeTimeout != writeTimeout {
		t.Errorf("write timeout of a new hub %v, want %v", h.writeTimeout, writeTimeout)
	}

	h.writeTimeout = time.Minute
	s := newStream()
	start := time.Now()
	done, end := serve(h, s)

	if got := next(t, s); got != "data: update\n\n" {
		t.Errorf("first chunk %q, want an update", got)
	}

	fromStart := time.Unix(0, s.flushDeadline.Load()).Sub(start)
	if fromStart < h.writeTimeout || fromStart > time.Since(start)+h.writeTimeout {
		t.Errorf("write deadline %v after the start, want %v", fromStart, h.writeTimeout)
	}

	for key, want := range map[string]string{
		"Cache-Control": "no-cache", "Content-Type": "text/event-stream", "X-Accel-Buffering": "no",
	} {
		if got := s.header.Get(key); got != want {
			t.Errorf("%s: %q, want %q", key, got, want)
		}
	}

	broadcast := time.Now()

	h.Broadcast()

	if got := next(t, s); got != "data: update\n\n" {
		t.Errorf("chunk after a broadcast %q, want an update", got)
	}

	if prior := s.priorDeadline.Load(); prior != 0 {
		t.Errorf("write deadline %v left set until the next send, want none", time.Unix(0, prior))
	}

	fromBroadcast := time.Unix(0, s.flushDeadline.Load()).Sub(broadcast)
	if fromBroadcast < h.writeTimeout || fromBroadcast > time.Since(broadcast)+h.writeTimeout {
		t.Errorf("write deadline %v after the broadcast, want %v", fromBroadcast, h.writeTimeout)
	}

	ended := time.Now()

	end()
	wait(t, done, "after the client left")

	if n := open(h); n != 0 {
		t.Errorf("%d streams open after the client left", n)
	}

	if prior := s.priorDeadline.Load(); prior != 0 {
		t.Errorf("write deadline %v of the last send left set at the end, want none", time.Unix(0, prior))
	}

	if last := time.Unix(0, s.deadline.Load()); last.Sub(ended) < h.writeTimeout {
		t.Errorf("write deadline %v at the end, want one %v after it", last, h.writeTimeout)
	}
}

// A stream sends a comment every keepalive interval.
func TestServeKeepalive(t *testing.T) {
	h := NewHub(Options{Keepalive: time.Millisecond, MaxStreams: 1})
	s := newStream()
	done, end := serve(h, s)

	defer func() {
		end()
		wait(t, done, "after the client left")
	}()

	next(t, s)

	if got := next(t, s); got != ": keepalive\n\n" {
		t.Errorf("chunk after a keepalive interval %q, want the keepalive comment", got)
	}
}

// A stream ends when setting a deadline, writing, flushing or clearing the deadline fails, on its first update, a later
// one or a keepalive.
func TestServeFails(t *testing.T) {
	for _, step := range []string{"deadline", "write", "flush", "clear"} {
		for _, when := range []string{"start", "update", "keepalive"} {
			h := NewHub(Options{Keepalive: time.Hour, MaxStreams: 1})
			if when == "keepalive" {
				h.opts.Keepalive = time.Millisecond
			}

			s := newStream()
			fail := map[string]*atomic.Bool{
				"deadline": &s.failDeadline, "write": &s.failWrite, "flush": &s.failFlush, "clear": &s.failClear,
			}[step]
			fail.Store(when == "start")

			done, end := serve(h, s)

			if when != "start" {
				next(t, s)
				fail.Store(true)

				if when == "update" {
					h.Broadcast()
				}
			}

			wait(t, done, step+" failing on "+when)
			end()

			if n := open(h); n != 0 {
				t.Errorf("%s failing on %s: %d streams open", step, when, n)
			}
		}
	}
}

// Past Options.MaxStreams a stream is refused, until another ends.
func TestServeFull(t *testing.T) {
	h := NewHub(Options{Keepalive: time.Hour, MaxStreams: 2})
	take := func() (end func()) {
		s := newStream()
		done, cancel := serve(h, s)
		next(t, s)

		return func() {
			cancel()
			wait(t, done, "after the client left")
		}
	}

	first, second := take(), take()
	defer second()

	refused(t, h, "with two streams open")
	first()
	take()()
}

// Close ends the open streams and refuses the next ones. A broadcast or another Close after it does nothing.
func TestClose(t *testing.T) {
	h := NewHub(Options{Keepalive: time.Hour, MaxStreams: 2})
	s := newStream()
	done, end := serve(h, s)

	defer end()

	next(t, s)
	h.Close()
	wait(t, done, "after Close")

	h.Broadcast()
	h.Close()
	refused(t, h, "after Close")

	if n := open(h); n != 0 {
		t.Errorf("%d streams open after Close", n)
	}
}

// A method other than GET gets a 405 that allows GET, and takes no stream.
func TestServeMethod(t *testing.T) {
	hub := NewHub(Options{Keepalive: time.Hour, MaxStreams: 1})

	for _, method := range []string{http.MethodHead, http.MethodPost} {
		recorder := httptest.NewRecorder()
		hub.ServeHTTP(recorder, httptest.NewRequest(method, "/api/stream", nil))

		if recorder.Code != http.StatusMethodNotAllowed || recorder.Header().Get("Allow") != http.MethodGet {
			t.Errorf("%s: status %d, Allow %q; want 405, GET", method, recorder.Code, recorder.Header().Get("Allow"))
		}

		if count := open(hub); count != 0 {
			t.Errorf("%s: %d streams open", method, count)
		}
	}
}
