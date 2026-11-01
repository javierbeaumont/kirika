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

| Command      | What it does                               |
|--------------|--------------------------------------------|
| `make build` | Compile every package                      |
| `make clean` | Remove the containers and the caches       |
| `make fmt`   | Format the code with gofumpt               |
| `make lint`  | Run golangci-lint and apply its fixes      |
| `make sh`    | Open a shell in the Go container           |
| `make test`  | Run the tests                              |
| `make vet`   | Report suspicious constructs with `go vet` |
