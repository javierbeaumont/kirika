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

// Package follow reads a log on an interval while it grows, so a live view can follow it.
package follow

import (
	"context"
	"log/slog"
	"time"

	"github.com/javierbeaumont/kirika/internal/ingest"
)

// Reader reads what a log gained since its last read, as an ingest.Reader does.
type Reader interface {
	Read() (ingest.Result, error)
}

// Run reads r now and then every interval until ctx ends, calling onChange, unless nil, after each read that counted a
// line. It logs to log, which the caller can tag with the log's path: a failed read as an error, once until the error
// changes or a read succeeds again, which it tells too; the counts of a read with unreadable lines as a warning; and
// those of any other read that took lines at debug level.
func Run(ctx context.Context, r Reader, interval time.Duration, log *slog.Logger, onChange func()) {
	t := time.NewTicker(interval)
	defer t.Stop()

	failed := "" // the error of the reads failing now

	for ctx.Err() == nil {
		res, err := r.Read()

		switch {
		case err != nil && err.Error() != failed:
			log.Error("read failed", "error", err)

			failed = err.Error()
		case err == nil && failed != "":
			log.Info("read again")

			failed = ""
		}

		if err == nil {
			report(log, res)

			if res.Counted > 0 && onChange != nil {
				onChange()
			}
		}

		select {
		case <-ctx.Done():
		case <-t.C:
		}
	}
}

// Logs the counts of a read that took lines: as a warning when some were unreadable, else at debug level.
func report(log *slog.Logger, res ingest.Result) {
	attrs := []any{
		"counted", res.Counted, "blank", res.Blank, "not_access", res.NotAccess, "dropped", res.Dropped,
		"malformed", res.Malformed, "binary", res.Binary, "too_long", res.TooLong, "bad_date", res.BadDate,
	}

	switch {
	case res.Malformed+res.Binary+res.TooLong+res.BadDate > 0:
		log.Warn("unreadable lines", attrs...)
	case res != (ingest.Result{}):
		log.Debug("lines read", attrs...)
	}
}
