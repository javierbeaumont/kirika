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

// Package sse tells the open dashboards, through Server-Sent Events, that the data changed.
package sse

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// How long a write to a stream may take: one that takes longer means its client stopped reading.
const writeTimeout = 10 * time.Second

// Options are the limits of a hub's streams.
type Options struct {
	Keepalive  time.Duration // how often a stream sends a comment, which keeps a proxy from closing it
	MaxStreams int           // the streams open at once, past which one is refused
}

// DefaultOptions returns the limits kirika uses when given none.
func DefaultOptions() Options {
	return Options{
		Keepalive:  25 * time.Second, // under the 60 seconds nginx waits on a quiet connection
		MaxStreams: 16,               // a few people with a few dashboards open each
	}
}

// Hub sends an update to every open stream when told the data changed.
type Hub struct {
	opts Options
	mu   sync.Mutex
	subs map[chan struct{}]struct{} // nil once closed
}

// NewHub returns a hub with the limits of o. It panics if one is not positive.
func NewHub(o Options) *Hub {
	switch {
	case o.Keepalive <= 0:
		panic(fmt.Sprintf("sse: keepalive %v is not positive", o.Keepalive))
	case o.MaxStreams <= 0:
		panic(fmt.Sprintf("sse: max streams %d is not positive", o.MaxStreams))
	}

	return &Hub{opts: o, subs: map[chan struct{}]struct{}{}}
}

// Broadcast tells every open stream that the data changed. It never blocks: a stream still waiting to send the last
// update sends one for both.
func (h *Hub) Broadcast() {
	h.mu.Lock()
	defer h.mu.Unlock()

	for ch := range h.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Close ends every open stream and refuses the next ones. Register it with http.Server.RegisterOnShutdown, or Shutdown
// waits for the streams until its context ends.
func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()

	for ch := range h.subs {
		close(ch)
	}

	h.subs = nil
}

// Returns a new stream's channel, or nil when the hub is closed or full.
func (h *Hub) subscribe() chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.subs == nil || len(h.subs) >= h.opts.MaxStreams {
		return nil
	}

	ch := make(chan struct{}, 1)
	h.subs[ch] = struct{}{}

	return ch
}

// Takes the stream of ch out of the broadcasts.
func (h *Hub) unsubscribe(ch chan struct{}) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
}

// ServeHTTP sends an update at once, for a client that reconnects, and another after each Broadcast, with a comment
// every Options.Keepalive. It ends when the client leaves, a write fails or the hub closes. A closed or full hub
// answers 503, and a method other than GET 405. Each write sets a deadline and flushes through http.ResponseController,
// so a wrapper of the server's ResponseWriter needs an Unwrap method: without one, a stream ends at once.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)

		return
	}

	updates := h.subscribe()
	if updates == nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)

		return
	}
	defer h.unsubscribe(updates)

	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no") // else nginx holds the events in its buffer

	controller := http.NewResponseController(w)
	send := func(message string) bool {
		if controller.SetWriteDeadline(time.Now().Add(writeTimeout)) != nil {
			return false
		}

		if _, err := io.WriteString(w, message); err != nil {
			return false
		}

		return controller.Flush() == nil
	}

	const update = "data: update\n\n"

	ticker := time.NewTicker(h.opts.Keepalive)
	defer ticker.Stop()

	for alive := send(update); alive; {
		select {
		case <-r.Context().Done():
			return
		case _, open := <-updates:
			alive = open && send(update)
		case <-ticker.C:
			alive = send(": keepalive\n\n")
		}
	}
}
