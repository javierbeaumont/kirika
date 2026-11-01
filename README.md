# kirika

A single static Go binary that turns HTTP access logs into private, self-hosted analytics. No JavaScript beacons, no
third-party trackers.

## Architecture Decision Records

Significant technology choices are recorded as ADRs in [`docs/adr/`](docs/adr/): the context, the alternatives
considered, the decision and its consequences.

| ADR                                              | Decision                                      |
|--------------------------------------------------|-----------------------------------------------|
| [0001](docs/adr/0001-substring-ua-classifier.md) | A substring heuristic to classify user agents |

## License

GPL-3.0-or-later. See [LICENSE](LICENSE) for the full text.
