# Contributing to kirika

## Development environment

Go runs in Docker, so the host needs only Docker with Compose, make and [pre-commit](https://pre-commit.com/). After
cloning, install the hooks once:

```sh
pre-commit install
```

They add the license header to new files, fix whitespace and line endings, lint the Go code (fixing what the linters
can), and check spelling, secrets, line length, YAML and that every file declares its license.

## Commands

| Command                 | What it does                               |
|-------------------------|--------------------------------------------|
| `make build`            | Compile every package                      |
| `make clean`            | Remove the containers and the caches       |
| `make fmt`              | Format the code with gofumpt               |
| `make lint`             | Run golangci-lint and apply its fixes      |
| `make sh`               | Open a shell in the Go container           |
| `make test`             | Run the unit and integration tests         |
| `make test-integration` | Run the integration tests and count them   |
| `make test-unit`        | Run the unit tests and count them          |
| `make vet`              | Report suspicious constructs with `go vet` |

## Tests

Tests come in two tiers, run apart. A unit test has no real dependency: it may read a fixture from `testdata/`, but
creates no file. An integration test uses a real store or file in a temporary directory. A test file names its tier and
carries it as a build tag:

| File                    | Build tag                |
|-------------------------|--------------------------|
| `*_integration_test.go` | `//go:build integration` |
| `*_unit_test.go`        | `//go:build unit`        |

A plain `*_test.go` holds the helpers both tiers use and no test. The hooks check all three. One test runs with its
tier's tag:

```sh
docker compose run --rm go go test -tags unit ./internal/kvstore -run TestName
```
