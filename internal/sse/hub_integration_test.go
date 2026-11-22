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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A write timeout short enough for a test to leave a stream idle past it.
const shortTimeout = 250 * time.Millisecond

// Opens a stream from the server at url with client, failing the test unless it has the event stream's type and starts
// with an update. Returns its response and a reader of the rest. It closes in the test's cleanup: a server closed
// earlier would wait for it.
func get(t *testing.T, client *http.Client, url string) (response *http.Response, reader *bufio.Reader) {
	t.Helper()

	response, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}

	t.Cleanup(func() { _ = response.Body.Close() })

	if got := response.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("Content-Type %q, want text/event-stream", got)
	}

	reader = bufio.NewReader(response.Body)

	for _, want := range []string{"data: update\n", "\n"} {
		if got, err := reader.ReadString('\n'); got != want || err != nil {
			t.Fatalf("read %q, %v; want %q", got, err, want)
		}
	}

	return response, reader
}

// Over HTTP, a client of the stream gets an update at once and another after a broadcast.
func TestServeHTTP(t *testing.T) {
	h := NewHub(DefaultOptions())

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	_, reader := get(t, &http.Client{Timeout: 5 * time.Second}, srv.URL)

	h.Broadcast()

	if got, err := reader.ReadString('\n'); got != "data: update\n" || err != nil {
		t.Errorf("read after a broadcast %q, %v; want an update", got, err)
	}
}

// Starts a server of hub over HTTP/1.1, or HTTP/2 with TLS, and returns it with a client. Its Shutdown closes hub.
func start(t *testing.T, hub *Hub, major int) (server *httptest.Server, client *http.Client) {
	t.Helper()

	server = httptest.NewUnstartedServer(hub)
	server.Config.RegisterOnShutdown(hub.Close)

	if major == 2 {
		server.EnableHTTP2 = true
		server.StartTLS()
	} else {
		server.Start()
	}

	t.Cleanup(server.Close)

	client = server.Client()
	client.Timeout = 5 * time.Second

	return server, client
}

// Over HTTP/1.1 and HTTP/2, http.Server.Shutdown ends an open stream once Close is registered with it, even one idle
// past the write timeout.
func TestShutdown(t *testing.T) {
	for _, major := range []int{1, 2} {
		for _, idle := range []time.Duration{0, 2 * shortTimeout} {
			t.Run(fmt.Sprintf("HTTP%d idle %v", major, idle), func(t *testing.T) {
				shutdownAfter(t, major, idle)
			})
		}
	}
}

// Opens a stream over HTTP/major, leaves it idle for idle, shuts down the server and checks that the stream ends.
func shutdownAfter(t *testing.T, major int, idle time.Duration) {
	hub := NewHub(DefaultOptions())
	hub.writeTimeout = shortTimeout
	server, client := start(t, hub, major)

	response, reader := get(t, client, server.URL)
	if response.ProtoMajor != major {
		t.Fatalf("protocol %s, want HTTP/%d", response.Proto, major)
	}

	time.Sleep(idle)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Config.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown: %v", err)
	}

	if rest, err := io.ReadAll(reader); len(rest) != 0 || err != nil {
		t.Errorf("read after Shutdown %q, %v; want the end of the stream", rest, err)
	}
}
