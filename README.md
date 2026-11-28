# kirika

A single static Go binary that turns HTTP access logs into private, self-hosted analytics.

## What sets it apart

- **No tracking code.** It reads the access logs your server already writes: no JavaScript, no cookies.
- **No IP addresses on disk.** Visitors and visits are counted through keyed hashes. A copy of the store still needs the
  care the logs need.
- **Small.** One binary and one data file, with no database server, built for modest machines such as a Raspberry Pi.
  The store keeps counters, not requests, so it grows with the different paths and referrers it sees rather than with
  your traffic.
- **Live.** It follows the log as it grows and tells the dashboard when the numbers change.

## Status

There is no release yet and nothing to run. Reading logs, counting and storing are written and tested.

## Development

[CONTRIBUTING.md](CONTRIBUTING.md) says how to build and test kirika.

## Architecture Decision Records

Significant decisions are recorded as ADRs in [`docs/adr/`](docs/adr/): the context, the alternatives considered, the
decision and its consequences.

| ADR                                              | Decision                                       |
|--------------------------------------------------|------------------------------------------------|
| [0001](docs/adr/0001-substring-ua-classifier.md) | A substring heuristic to classify user agents  |
| [0002](docs/adr/0002-bbolt.md)                   | bbolt as the store                             |
| [0003](docs/adr/0003-traffic-classes.md)         | Traffic classes to filter what is counted      |
| [0004](docs/adr/0004-hyperloglog.md)             | HyperLogLog for unique visitors                |
| [0005](docs/adr/0005-server-sent-events.md)      | Server-Sent Events for live updates            |
| [0006](docs/adr/0006-yearly-sketch-keys.md)      | A key per year for the unique-visitor sketches |

## License

GPL-3.0-or-later. See [LICENSE](LICENSE) for the full text.
