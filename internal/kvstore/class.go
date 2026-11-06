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

import "errors"

// Status groups of a request.
const (
	groupCorrect = iota // a valid status code
	groupOther          // the rest of 1xx, 2xx and 3xx, such as redirects
	groupError          // 4xx, 5xx, no status and 600-999
	groupCount
)

// The number of classes: every status group, for humans and for bots.
const numClasses = 2 * groupCount

var errBadFilter = errors.New("kvstore: unknown filter value")

// A request's traffic class: its status group and whether a bot made it.
type class uint8

func newClass(bot bool, group int) class {
	c := class(group << 1)
	if bot {
		c |= 1
	}

	return c
}

func (c class) bot() bool {
	return c&1 == 1
}

func (c class) group() int {
	return int(c >> 1)
}

// Audience filters requests by who made them.
type Audience uint8

// Audiences.
const (
	Humans Audience = iota
	Bots
	AllAudiences
)

// Kind filters requests by what they asked for.
type Kind uint8

// Kinds.
const (
	AllKinds Kind = iota
	PageKind
	FileKind
)

// Status filters requests by their status group.
type Status uint8

// Statuses.
const (
	Correct Status = iota // a valid status code
	Errors                // 4xx, 5xx, no status and 600-999
	AllStatuses
)

// Filter picks what a read counts. Its zero value is the default view: human requests with a valid status code, pages
// and files alike.
type Filter struct {
	Audience Audience
	Kind     Kind
	Status   Status
}

func (f Filter) check() error {
	if f.Audience > AllAudiences || f.Kind > FileKind || f.Status > AllStatuses {
		return errBadFilter
	}

	return nil
}

// Reports whether the filter counts class c.
func (f Filter) has(c class) bool {
	switch {
	case f.Audience == Humans && c.bot(), f.Audience == Bots && !c.bot():
		return false
	case f.Status == Correct:
		return c.group() == groupCorrect
	case f.Status == Errors:
		return c.group() == groupError
	default:
		return true
	}
}

// Adds up the classes of t the filter counts and keeps the part of its kind, visits being part of pages. ok is false
// when it counts none.
func (f Filter) sum(t tally) (c Counts, ok bool) {
	for _, e := range t {
		if f.has(e.class) {
			c.add(e.Counts)

			ok = true
		}
	}

	switch f.Kind {
	case PageKind:
		c.HitBandwidth, c.Hits = c.PageBandwidth, c.Pages
	case FileKind:
		c = Counts{HitBandwidth: c.HitBandwidth - c.PageBandwidth, Hits: c.Hits - c.Pages}
	}

	return c, ok
}
