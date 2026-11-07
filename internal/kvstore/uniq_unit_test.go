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

package kvstore

import (
	"bytes"
	"testing"
)

func TestClientKey(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.1":            "192.0.2.1",
		"::ffff:192.0.2.1":     "192.0.2.1",
		"2001:DB8::1":          "2001:db8::1",
		"2001:db8:0:0:0:0:0:1": "2001:db8::1",
		"fe80::1%eth0":         "fe80::1%eth0",
		"Client.Example":       "client.example",
		"192.0.2.1:80":         "192.0.2.1:80",
	} {
		if got := clientKey(in); got != want {
			t.Errorf("clientKey(%q) = %q, want %q", in, got, want)
		}
	}
}

// A loaded sketch does not point into its stored bytes, which belong to bbolt and move when a later write remaps the
// file.
func TestLoadSketchCopies(t *testing.T) {
	dense := blob(t, hllPrecision, 20000)
	if dense[3] != 0 {
		t.Fatal("the sketch is sparse; only a dense one can point into its input")
	}

	sk, ok := loadSketch(dense)
	if !ok {
		t.Fatal("loadSketch refused a valid sketch")
	}

	before := sk.Estimate()

	for i := range dense {
		dense[i] = 0xff
	}

	if after := sk.Estimate(); after != before {
		t.Errorf("the estimate changed from %d to %d with the stored bytes", before, after)
	}
}

// Each byte of a sparse and a dense sketch is altered, and whatever loadSketch accepts is merged: a fault inside the
// library would stop the process, past what a test or recover can catch.
func TestLoadSketchCorrupt(t *testing.T) {
	for _, b := range [][]byte{blob(t, hllPrecision, 100), blob(t, hllPrecision, 20000)} {
		for i := range b {
			for _, v := range []byte{0, 1, 0x7f, 0x80, 0xff} {
				c := bytes.Clone(b)
				c[i] = v

				if sk, ok := loadSketch(c); ok {
					acc := newSketch()
					if err := acc.Merge(sk); err != nil {
						t.Fatalf("byte %d = %#x: merge: %v", i, v, err)
					}

					acc.Estimate()
				}
			}
		}
	}
}
