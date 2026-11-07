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

	"github.com/javierbeaumont/kirika/internal/logparse"
)

// Returns the estimate of each of the batch's sketches, by key.
func estimates(b *Batch) map[string]uint64 {
	out := map[string]uint64{}
	for k, sk := range b.u {
		out[k] = sk.Estimate()
	}

	return out
}

// A client counts once, from its first page, in the sketch of its host in any case, its month and its class. A request
// with no page or no client adds nothing.
func TestUnique(t *testing.T) {
	next := base.AddDate(0, 1, 0)

	evs := visits("h", 0, 1000, at(1, 0))
	evs = append(evs, visits("H", 0, 1000, at(2, 0))...)
	evs = append(evs, visits("other", 1000, 2000, at(1, 0))...)
	evs = append(evs, visits("h", 1000, 2000, next)...)
	evs = append(evs,
		page("no-client", "/", 200, 1, base),
		from(ip(0), page("files", "/logo.png", 200, 1, base)),
		from(ip(0), page("mixed", "/logo.png", 200, 1, base)),
		from(ip(0), page("mixed", "/", 200, 1, base)),
		from(ip(1), page("mixed", "/app.css", 200, 1, base)),
	)

	human := newClass(false, groupCorrect)
	jan, feb := base.Format("200601"), next.Format("200601")
	want := map[string]int{
		string(uniqKey("h", jan, human)):     1000,
		string(uniqKey("h", feb, human)):     1000,
		string(uniqKey("mixed", jan, human)): 1,
		string(uniqKey("other", jan, human)): 1000,
	}

	got := estimates(applied(evs...))
	for k, n := range want {
		if !near(got[k], n) {
			t.Errorf("sketch %q = %d, want about %d", k, got[k], n)
		}
	}

	for k, n := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("sketch %q = %d, want none", k, n)
		}
	}
}

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

// A client counts once in any of its forms.
func TestUniqueClientForms(t *testing.T) {
	var evs []logparse.Event
	for _, c := range []string{
		"192.0.2.1", "::ffff:192.0.2.1", "2001:db8::1", "2001:DB8:0:0:0:0:0:1", "a.example", "A.Example",
	} {
		evs = append(evs, from(c, page("h", "/", 200, 1, base)))
	}

	key := string(uniqKey("h", base.Format("200601"), newClass(false, groupCorrect)))
	if got := estimates(applied(evs...)); len(got) != 1 || got[key] != 3 {
		t.Errorf("sketches = %v, want 3 clients under %q only", got, key)
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
