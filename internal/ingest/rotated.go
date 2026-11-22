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
	"cmp"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/javierbeaumont/kirika/internal/kvstore"
)

// The length of a file's first bytes that tell its compression: the longest is bzip2's header and block magic.
const magicLen = 10

// The first bytes of gzip, which a read decompresses, and of xz and zstd, which it cannot.
var (
	gzipMagic = []byte{0x1f, 0x8b}
	xzMagic   = []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}
	zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}
)

// Reports whether head, a file's first bytes, opens bzip2, xz or zstd. bzip2's "BZh" alone could open a line of text,
// so it wants the block size and the first block's magic too.
func otherCompression(head []byte) bool {
	bzip2 := len(head) >= magicLen && bytes.HasPrefix(head, []byte("BZh")) && head[3] >= '1' && head[3] <= '9' &&
		string(head[4:magicLen]) == "1AY&SY"

	return bzip2 || bytes.HasPrefix(head, xzMagic) || bytes.HasPrefix(head, zstdMagic)
}

// Returns the globs of the rotated files of the log named base: logrotate's numbered names and its dated ones, and
// Caddy's, which put a time between the name and its extension. Each wants digits after the log's name, and Caddy's its
// default time, so that another log beside it, such as access-api.log or access-8080.log, does not match.
func defaultRotated(base string) []string {
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)

	return []string{
		escapeGlob(base) + ".[0-9]*",
		escapeGlob(base) + "-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]*",
		escapeGlob(stem) + "-[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T*" + escapeGlob(ext) + "*",
	}
}

// Returns name with the characters filepath.Match reads as a pattern escaped: each of *, ? and [ in a class of its own,
// which Windows takes too, and a backslash with a backslash, but on Windows, where it separates paths.
func escapeGlob(name string) string {
	var escaped strings.Builder

	for _, char := range name {
		switch {
		case strings.ContainsRune("*?[", char):
			escaped.WriteString("[" + string(char) + "]")
		case char == '\\' && filepath.Separator != '\\':
			escaped.WriteString(`\\`)
		default:
			escaped.WriteRune(char)
		}
	}

	return escaped.String()
}

// A rotated file of the log, open, so that a rotation after it was found does not change the file read.
type rotatedFile struct {
	file *os.File
	info fs.FileInfo
	name string
}

// Returns the regular files r.rotated matches, open, newest first, but current. Of two names of one file, or of a file
// and its gzip copy, it keeps one: the first, or the copy's source. It warns of a file it cannot open. The caller
// closes the files.
func (r *Reader) rotatedFiles(current *os.File) ([]rotatedFile, error) {
	currentInfo, err := current.Stat()
	if err != nil {
		return nil, err
	}

	var files []rotatedFile

	for _, pattern := range r.rotated {
		names, err := filepath.Glob(pattern)
		if err != nil {
			closeRotated(files)

			return nil, err
		}

		for _, name := range names {
			if rotated, ok := r.openRotated(name, currentInfo, files); ok {
				files = append(files, rotated)
			}
		}
	}

	files = slices.DeleteFunc(files, func(file rotatedFile) bool {
		source, zipped := strings.CutSuffix(file.name, ".gz")
		copied := zipped && slices.ContainsFunc(files, func(other rotatedFile) bool { return other.name == source })

		if copied {
			_ = file.file.Close() // read only: a failed close loses nothing
		}

		return copied
	})

	slices.SortFunc(files, newerFirst)

	return files, nil
}

// Returns the file name open, unless it is no regular file, current, one of files or gone; it warns of one it cannot
// open.
func (r *Reader) openRotated(name string, currentInfo fs.FileInfo, files []rotatedFile) (rotatedFile, bool) {
	file, err := os.Open(name)
	if errors.Is(err, fs.ErrNotExist) { // compressed or deleted since the glob
		return rotatedFile{}, false
	}

	if err != nil {
		r.log.Warn("a rotated file cannot be opened", "path", r.path, "file", name, "error", err)

		return rotatedFile{}, false
	}

	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || os.SameFile(info, currentInfo) ||
		slices.ContainsFunc(files, func(other rotatedFile) bool { return os.SameFile(other.info, info) }) {
		_ = file.Close() // read only: a failed close loses nothing

		return rotatedFile{}, false
	}

	return rotatedFile{file, info, name}, true
}

// Closes files.
func closeRotated(files []rotatedFile) {
	for _, file := range files {
		_ = file.file.Close() // read only: a failed close loses nothing
	}
}

// Orders the rotated files a and b newer first: two of logrotate's numbered names of one log by their number, the lower
// the newer, as its compression may change a file's time; any other two by time, then by name, the later the newer, as
// dates and times sort.
func newerFirst(a, b rotatedFile) int {
	if order, ok := byNumber(a.name, b.name); ok {
		return order
	}

	if order := b.info.ModTime().Compare(a.info.ModTime()); order != 0 {
		return order
	}

	return strings.Compare(b.name, a.name)
}

// Orders a and b by the number logrotate gives them, the lower first, if both have one after the same name.
func byNumber(a, b string) (order int, ok bool) {
	logA, numberA, okA := rotationNumber(a)
	logB, numberB, okB := rotationNumber(b)

	if !okA || !okB || logA != logB {
		return 0, false
	}

	return cmp.Compare(numberA, numberB), true
}

// Returns the name of the log and the number logrotate gives the file name, as access.log and 2 in access.log.2.gz: the
// digits after its last dot, which follows no digit, as the dot in a time's milliseconds does.
func rotationNumber(name string) (log string, number int, ok bool) {
	name = strings.TrimSuffix(name, ".gz")
	dot := strings.LastIndexByte(name, '.')

	if dot < 1 || name[dot-1] >= '0' && name[dot-1] <= '9' {
		return "", 0, false
	}

	number, err := strconv.Atoi(name[dot+1:])

	return name[:dot], number, err == nil
}

// Reads the rest of the rotated file that holds state's line, then each rotated file newer than it, as readNewer does,
// and reports whether it found that line. A state of no line read names the last line of the log before, which a read
// looks for the same way. It warns when no rotated file it can read holds a line of the log it read last: lines written
// since may be lost.
func (r *Reader) readRotated(ctx context.Context, current *os.File, state kvstore.LogState, limit time.Time,
	progress *scan,
) (bool, error) {
	files, err := r.rotatedFiles(current)
	if err != nil {
		return false, err
	}

	defer closeRotated(files)

	unread := make([]bool, len(files))

	for i, file := range files {
		if err := ctx.Err(); err != nil {
			return false, err
		}

		got, err := r.readRotatedFile(ctx, file, &state, limit, progress)
		if err != nil {
			return false, err
		}

		if got == taken {
			return true, r.readNewer(ctx, files[:i], unread, limit, progress)
		}

		unread[i] = got == skipped
	}

	if state.Line > 0 {
		r.log.Warn("the last line read is in no rotated file, so lines written since may be lost", "path", r.path,
			"rotated", r.rotated)
	}

	return false, nil
}

// Reads each of files whole, oldest first, but those unread marks; files come newest first.
func (r *Reader) readNewer(ctx context.Context, files []rotatedFile, unread []bool, limit time.Time,
	progress *scan,
) error {
	for i, file := range slices.Backward(files) {
		if unread[i] {
			continue
		}

		if _, err := r.readRotatedFile(ctx, file, nil, limit, progress); err != nil {
			return err
		}
	}

	return nil
}

// An error of a rotated file's content, which ends the read of that file only.
type contentError struct{ error }

func (e contentError) Unwrap() error { return e.error }

// A reader whose errors, but io.EOF, are contentErrors.
type contentReader struct{ io.Reader }

func (c contentReader) Read(buffer []byte) (int, error) {
	count, err := c.Reader.Read(buffer)
	if err != nil && !errors.Is(err, io.EOF) {
		err = contentError{err}
	}

	return count, err
}

// What a read made of a rotated file.
type rotatedRead int

const (
	missed  rotatedRead = iota // it did not hold the line sought
	taken                      // its lines after the one sought, or all of them
	skipped                    // compressed in another format than gzip, or with a gzip header that fails
)

// Reads the rotated file into progress: after state's line when state is not nil, and only if that line is there; else
// the whole file. It decompresses gzip and skips another compressed format. An error of the file's content ends its
// read. Each skip warns. The lines after a state of no line read count from 1.
func (r *Reader) readRotatedFile(ctx context.Context, rotated rotatedFile, state *kvstore.LogState, limit time.Time,
	progress *scan,
) (rotatedRead, error) {
	file, name := rotated.file, rotated.name

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return skipped, r.skipRotated(name, contentError{err})
	}

	lines := bufio.NewReader(contentReader{file})
	head, _ := lines.Peek(magicLen) // an error comes back on the next read

	zipped := bytes.HasPrefix(head, gzipMagic)

	switch {
	case zipped:
		unzipped, err := gzip.NewReader(lines)
		if err != nil {
			return skipped, r.skipRotated(name, contentError{err})
		}

		lines = bufio.NewReader(contentReader{unzipped})
	case otherCompression(head):
		r.log.Warn("a rotated file is compressed in a format a read cannot take", "path", r.path, "file", name)

		return skipped, nil
	}

	var offset, lineNum int64

	if state != nil { // a file that fails before the line sought does not hold it: a whole read may take its lines
		var err error

		if zipped {
			_, err = io.CopyN(io.Discard, lines, state.Offset)
		} else if _, err = file.Seek(state.Offset, io.SeekStart); err == nil {
			lines.Reset(contentReader{file})
		}

		if err != nil {
			return missed, nil
		}

		logLine, size, more, err := next(lines, state.Offset)
		if err != nil || !more || logLine.sum != state.Sum {
			return missed, nil
		}

		offset, lineNum = state.Offset+size, state.Line
	}

	return taken, r.skipRotated(name, r.readLines(ctx, nil, name, lines, offset, lineNum, limit, progress))
}

// Returns err, or warns of it and returns nil when it is an error of the content of the rotated file name.
func (r *Reader) skipRotated(name string, err error) error {
	var content contentError
	if !errors.As(err, &content) {
		return err
	}

	r.log.Warn("a rotated file is unreadable from here on", "path", r.path, "file", name, "error", content.error)

	return nil
}
