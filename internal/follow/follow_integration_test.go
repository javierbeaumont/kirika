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

package follow

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/javierbeaumont/kirika/internal/ingest"
	"github.com/javierbeaumont/kirika/internal/kvstore"
	"github.com/javierbeaumont/kirika/internal/logparse"
)

// A follower counts the lines a log gains into the store, and calls onChange after the read that counted them.
func TestRunLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")

	db, err := kvstore.Open(filepath.Join(dir, "kirika.db"), time.Second, "UTC")
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	t.Cleanup(func() { _ = db.Close() })

	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	options := ingest.DefaultOptions()
	options.DefaultHost = "h"

	logReader, err := ingest.New(db, path, logparse.ParseNCSA, options)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	t.Cleanup(func() {
		if err := logReader.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	changed, done := make(chan struct{}, 8), make(chan struct{})

	go func() {
		Run(ctx, logReader, time.Millisecond, slog.New(slog.DiscardHandler), func() { changed <- struct{}{} })
		close(done)
	}()

	line := `192.0.2.1 - - [01/Jan/2000:00:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "Mozilla/5.0 (X11; Linux x86_64)"`
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("append: %v", err)
	}

	select {
	case <-changed:
	case <-time.After(5 * time.Second):
		t.Error("no change within 5 seconds of a new line")
	}

	cancel()
	<-done

	if c, err := db.Totals("h", "2000", kvstore.Filter{}); err != nil || c.Hits != 1 {
		t.Errorf("Totals = %+v, %v; want 1 hit", c, err)
	}
}
