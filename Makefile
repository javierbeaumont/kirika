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
# No TTY: pre-commit gives hooks no terminal on stdin, which older Compose versions do not detect.
LINT := docker compose run --rm -T lint
# The test tiers, each the build tag of its test files.
TIERS := unit integration

.PHONY: build clean fmt lint sh test test-integration test-unit vet

build:
	$(GO) go build ./...

# Also removes the caches.
clean:
	docker compose down -v

fmt:
	$(LINT) golangci-lint fmt

# Applies the fixes the linters can make.
lint:
	$(LINT) sh -c 'for tier in $(TIERS); do golangci-lint run --fix --build-tags $$tier || exit; done'

sh:
	$(GO) sh

test: $(TIERS:%=test-%)

# Also prints how many tests the tier has.
$(TIERS:%=test-%): test-%:
	$(GO) sh -c 'go test -tags $* ./... && echo "$*: $$(go test -tags $* -list . ./... | grep -c ^Test) tests"'

vet:
	$(GO) sh -c 'for tier in $(TIERS); do go vet -tags $$tier ./... || exit; done'
