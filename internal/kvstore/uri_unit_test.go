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
	"math/rand/v2"
	"testing"
)

// An escape is decoded when it stands for an unreserved character and keeps upper-case hex otherwise; a reserved
// character stays as written, and any other byte written raw is escaped.
func TestCanonicalURI(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/a/b", "/a/b"},
		{"%7E/%7e", "~/~"},
		{"/%41%5A%61%7A%30%39%2D%2E%5F", "/AZaz09-._"},
		{"/%25%2f%3a%40%5b%5D%21%3D%3F%23", "/%25%2F%3A%40%5B%5D%21%3D%3F%23"},
		{"/%20%22%3c%3E%5C%5e%60%7B%7c%7D%00%1F%7F", "/%20%22%3C%3E%5C%5E%60%7B%7C%7D%00%1F%7F"},
		{"/a b\"<>\\^`{|}\x00\x1f\x7f", "/a%20b%22%3C%3E%5C%5E%60%7B%7C%7D%00%1F%7F"},
		{"/:@!$&'()*+,;=[]?#", "/:@!$&'()*+,;=[]?#"},
		{"/%", "/%25"},
		{"/%4", "/%254"},
		{"/%4G%G4", "/%254G%25G4"},
		{"/%/0%:0%@0%G0%`0%g0", "/%25/0%25:0%25@0%25G0%25%600%25g0"},
		{"/a%C3%B1o", "/a%C3%B1o"},
		{"/a%c3%b1o", "/a%C3%B1o"},
		{"/a\u00f1o", "/a%C3%B1o"},
		{"/a%c3\xb1o", "/a%C3%B1o"},
		{"/a%F1o/a\xf1o", "/a%F1o/a%F1o"},
		{"/x\u202etxt.exe", "/x%E2%80%AEtxt.exe"},
		{"/\U0001f600", "/%F0%9F%98%80"},
		{"https://xn--caf-dma.example/wiki/A%c3%b1o", "https://xn--caf-dma.example/wiki/A%C3%B1o"},
		{"http://[2001:db8::1]:8080/a%2fb", "http://[2001:db8::1]:8080/a%2Fb"},
	} {
		if got := canonicalURI(tc.in); got != tc.want {
			t.Errorf("canonicalURI(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Whatever its input, canonicalURI returns ASCII in which each character is one a URI holds as itself or an escape, in
// upper case, of any but an unreserved one, and converting it again changes nothing.
func TestCanonicalURIForm(t *testing.T) {
	const alphabet = "%%%%0123456789ABCDEFabcdefg/ \x00{\x80\xa9\xc3\xe2\xff"

	random := rand.New(rand.NewPCG(1, 2))

	for range 20000 {
		in := make([]byte, random.IntN(12))
		for i := range in {
			in[i] = alphabet[random.IntN(len(alphabet))]
		}

		got := canonicalURI(string(in))
		if again := canonicalURI(got); again != got || !canonical(got) {
			t.Fatalf("canonicalURI(%q) = %q, converted again %q", in, got, again)
		}
	}
}

// Reports whether each character of converted is one a URI holds as itself or the start of an escape, in upper case, of
// any but an unreserved one.
func canonical(converted string) bool {
	for i := 0; i < len(converted); i++ {
		if octet := converted[i]; octet == '%' {
			if i+2 >= len(converted) || !upperHexDigit(converted[i+1]) || !upperHexDigit(converted[i+2]) ||
				isUnreserved(unhex(converted[i+1])<<4|unhex(converted[i+2])) {
				return false
			}
		} else if !rawASCII(octet) {
			return false
		}
	}

	return true
}

func upperHexDigit(octet byte) bool {
	return '0' <= octet && octet <= '9' || 'A' <= octet && octet <= 'F'
}

// A path with nothing to convert comes back as it is, with no allocation.
func TestCanonicalURIPlain(t *testing.T) {
	const path = "/blog/2000/01/a-post_1.html"

	allocs := testing.AllocsPerRun(100, func() {
		if canonicalURI(path) != path {
			t.Fatal("a plain path changed")
		}
	})
	if allocs != 0 {
		t.Errorf("%v allocations for a plain path, want 0", allocs)
	}
}
