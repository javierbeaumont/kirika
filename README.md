# kirika

A single static Go binary that turns HTTP access logs into private, self-hosted analytics. No JavaScript beacons, no
third-party trackers.

## Architecture Decision Records

Significant technology choices are recorded as ADRs in [`docs/adr/`](docs/adr/): the context, the alternatives
considered, the decision and its consequences.

| ADR                                              | Decision                                      |
|--------------------------------------------------|-----------------------------------------------|
| [0001](docs/adr/0001-substring-ua-classifier.md) | A substring heuristic to classify user agents |
| [0002](docs/adr/0002-bbolt.md)                   | bbolt as the store                            |
| [0003](docs/adr/0003-traffic-classes.md)         | Traffic classes to filter what is counted     |
| [0004](docs/adr/0004-hyperloglog.md)             | HyperLogLog for unique visitors               |

## License

GPL-3.0-or-later. See [LICENSE](LICENSE) for the full text.
