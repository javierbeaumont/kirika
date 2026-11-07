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

//go:build integration

package sse

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Opens a stream from the server at url, failing the test unless it has the event stream's type and starts with an
// update. It closes in the test's cleanup: a server closed earlier would wait for it.
func get(t *testing.T, url string) *bufio.Reader {
	t.Helper()

	client := &http.Client{Timeout: 5 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}

	t.Cleanup(func() { _ = resp.Body.Close() })

	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("Content-Type %q, want text/event-stream", got)
	}

	br := bufio.NewReader(resp.Body)

	for _, want := range []string{"data: update\n", "\n"} {
		if got, err := br.ReadString('\n'); got != want || err != nil {
			t.Fatalf("read %q, %v; want %q", got, err, want)
		}
	}

	return br
}

// Over HTTP, a client of the stream gets an update at once and another after a broadcast.
func TestServeHTTP(t *testing.T) {
	h := NewHub(DefaultOptions())

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	br := get(t, srv.URL)

	h.Broadcast()

	if got, err := br.ReadString('\n'); got != "data: update\n" || err != nil {
		t.Errorf("read after a broadcast %q, %v; want an update", got, err)
	}
}

// http.Server.Shutdown ends an open stream once Close is registered with it.
func TestShutdown(t *testing.T) {
	h := NewHub(DefaultOptions())

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	srv.Config.RegisterOnShutdown(h.Close)
	br := get(t, srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Config.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown: %v", err)
	}

	if rest, err := io.ReadAll(br); len(rest) != 0 || err != nil {
		t.Errorf("read after Shutdown %q, %v; want the end of the stream", rest, err)
	}
}
