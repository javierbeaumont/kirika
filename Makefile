# kirika: private analytics from HTTP access logs
#
# Copyright (C) 2026 Javier Beaumont <javierbeaumont@users.noreply.github.com>
#
# This file is part of kirika.
#
# kirika is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# kirika is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with kirika. If not, see <https://www.gnu.org/licenses/>.

GO := docker compose run --rm go

.PHONY: build clean fmt sh

build:
	$(GO) go build ./...

# Also removes the Go module and build caches.
clean:
	docker compose down -v

fmt:
	$(GO) gofmt -w .

sh:
	$(GO) sh
