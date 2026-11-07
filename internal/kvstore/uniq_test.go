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

package kvstore

import (
	"fmt"
	"testing"

	"github.com/axiomhq/hyperloglog"
)

// Returns the i-th of a range of distinct IPv4 addresses.
func ip(i int) string {
	return fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)
}

// Returns the encoding of a sketch of n distinct IPs at precision p.
func blob(t *testing.T, p uint8, n int) []byte {
	t.Helper()

	sk, err := hyperloglog.NewSketch(p, true)
	if err != nil {
		t.Fatalf("new sketch: %v", err)
	}

	for i := range n {
		sk.Insert([]byte(ip(i)))
	}

	b, err := sk.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	return b
}
