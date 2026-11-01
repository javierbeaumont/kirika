# Contributing to kirika

## Development environment

Go runs in Docker, so the host needs only Docker with Compose, make and [pre-commit](https://pre-commit.com/). After
cloning, install the hooks once:

```sh
pre-commit install
```

They add the license header to new files, fix whitespace and line endings, and check spelling, secrets, line length,
YAML and that every file declares its license.

## Commands

| Command      | What it does                                             |
|--------------|----------------------------------------------------------|
| `make build` | Compile every package                                    |
| `make clean` | Remove the containers and the Go module and build caches |
| `make fmt`   | Format the code with `gofmt`                             |
| `make sh`    | Open a shell in the Go container                         |
