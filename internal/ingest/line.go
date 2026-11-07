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

package ingest

import (
	"bufio"
	"bytes"
	"errors"
	"hash/fnv"
	"io"
)

// The longest line kept, in bytes: longer ones are unreadable, so a file with no newline cannot fill the memory.
const maxLine = 1 << 20

// The text between two newlines of a log, with where it starts and its checksum.
type line struct {
	long  bool    // longer than maxLine
	start int64   // its offset in the log
	sum   [8]byte // FNV-1a of 64 bits over its text
	text  []byte  // without its newline and a carriage return before it; nil when long
}

// Reads the line that starts at offset start. n is the line's length in the log, newline included. more is false at the
// end of the log, where a last line with no newline yet waits for the next read.
func next(br *bufio.Reader, start int64) (l line, n int64, more bool, err error) {
	h := fnv.New64a()
	l.start = start
	add := func(p []byte) {
		h.Write(p) // never fails

		if !l.long && len(l.text)+len(p) > maxLine {
			l.long, l.text = true, nil
		}

		if !l.long {
			l.text = append(l.text, p...)
		}
	}

	cr := false // a carriage return held back: it belongs to the line unless the newline comes right after it

	for {
		chunk, err := br.ReadSlice('\n')
		n += int64(len(chunk))

		switch {
		case err == nil:
			chunk = chunk[:len(chunk)-1]
			if cr && len(chunk) > 0 {
				add([]byte{'\r'})
			}

			add(bytes.TrimSuffix(chunk, []byte{'\r'}))
			copy(l.sum[:], h.Sum(nil))

			return l, n, true, nil
		case errors.Is(err, bufio.ErrBufferFull):
			if cr {
				add([]byte{'\r'})
			}

			cr = chunk[len(chunk)-1] == '\r'
			if cr {
				chunk = chunk[:len(chunk)-1]
			}

			add(chunk)
		case errors.Is(err, io.EOF):
			return l, n, false, nil
		default:
			return l, n, false, err
		}
	}
}
