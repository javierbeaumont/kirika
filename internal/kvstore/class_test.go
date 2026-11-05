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
	"errors"
	"testing"
)

// Checks which of the six classes every audience and status counts.
func TestFilterHas(t *testing.T) {
	human := func(g int) class { return newClass(false, g) }
	bot := func(g int) class { return newClass(true, g) }

	for _, tc := range []struct {
		f    Filter
		want []class
	}{
		{Filter{}, []class{human(groupCorrect)}},
		{Filter{Status: Errors}, []class{human(groupError)}},
		{Filter{Status: AllStatuses}, []class{human(groupCorrect), human(groupOther), human(groupError)}},
		{Filter{Audience: Bots}, []class{bot(groupCorrect)}},
		{Filter{Audience: Bots, Status: Errors}, []class{bot(groupError)}},
		{Filter{Audience: Bots, Status: AllStatuses}, []class{bot(groupCorrect), bot(groupOther), bot(groupError)}},
		{Filter{Audience: AllAudiences}, []class{human(groupCorrect), bot(groupCorrect)}},
		{Filter{Audience: AllAudiences, Status: Errors}, []class{human(groupError), bot(groupError)}},
		{Filter{Audience: AllAudiences, Status: AllStatuses}, []class{0, 1, 2, 3, 4, 5}},
	} {
		var got []class

		for c := range class(numClasses) {
			if tc.f.has(c) {
				got = append(got, c)
			}
		}

		if !sameClasses(got, tc.want) {
			t.Errorf("%+v counts %v, want %v", tc.f, got, tc.want)
		}
	}
}

func sameClasses(a, b []class) bool {
	if len(a) != len(b) {
		return false
	}

	seen := map[class]bool{}
	for _, c := range a {
		seen[c] = true
	}

	for _, c := range b {
		if !seen[c] {
			return false
		}
	}

	return true
}

// A filter adds up its classes and keeps the part of its kind.
func TestFilterSum(t *testing.T) {
	tl := tally{
		{newClass(false, groupCorrect), Counts{HitBandwidth: 100, Hits: 10, PageBandwidth: 60, Pages: 4}},
		{newClass(false, groupError), Counts{HitBandwidth: 7, Hits: 1, PageBandwidth: 7, Pages: 1}},
		{newClass(true, groupCorrect), Counts{HitBandwidth: 50, Hits: 5, PageBandwidth: 20, Pages: 2}},
	}

	for _, tc := range []struct {
		f    Filter
		want Counts
		ok   bool
	}{
		{Filter{}, Counts{HitBandwidth: 100, Hits: 10, PageBandwidth: 60, Pages: 4}, true},
		{Filter{Kind: PageKind}, Counts{HitBandwidth: 60, Hits: 4, PageBandwidth: 60, Pages: 4}, true},
		{Filter{Kind: FileKind}, Counts{HitBandwidth: 40, Hits: 6}, true},
		{Filter{Audience: Bots}, Counts{HitBandwidth: 50, Hits: 5, PageBandwidth: 20, Pages: 2}, true},
		{Filter{Status: Errors}, Counts{HitBandwidth: 7, Hits: 1, PageBandwidth: 7, Pages: 1}, true},
		{
			Filter{Audience: AllAudiences, Status: AllStatuses},
			Counts{HitBandwidth: 157, Hits: 16, PageBandwidth: 87, Pages: 7},
			true,
		},
		{Filter{Audience: Bots, Status: Errors}, Counts{}, false},
	} {
		if got, ok := tc.f.sum(tl); got != tc.want || ok != tc.ok {
			t.Errorf("%+v: sum = %+v, %v; want %+v, %v", tc.f, got, ok, tc.want, tc.ok)
		}
	}
}

func TestFilterCheck(t *testing.T) {
	for a := range AllAudiences + 1 {
		for k := range FileKind + 1 {
			for s := range AllStatuses + 1 {
				if err := (Filter{a, k, s}).check(); err != nil {
					t.Errorf("Filter{%d, %d, %d}: %v", a, k, s, err)
				}
			}
		}
	}

	for _, f := range []Filter{{Audience: AllAudiences + 1}, {Kind: FileKind + 1}, {Status: AllStatuses + 1}} {
		if err := f.check(); !errors.Is(err, errBadFilter) {
			t.Errorf("%+v: err = %v, want errBadFilter", f, err)
		}
	}
}
