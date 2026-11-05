# ADR-0003: Traffic classes to filter what is counted

**Date:** 2026-11-05 **Status:** Accepted

## Context

An access log mixes human requests with those of crawlers and scanners, and correct responses with redirects and errors.
The default figures must cover humans with a correct response. Bot traffic, errors and redirects must remain queryable,
and so must pages and files separately. After log rotation the store is the only record: a distinction not stored at
counting time cannot be recovered.

## Alternatives considered

| Option                                   | Reason rejected                                      |
|------------------------------------------|------------------------------------------------------|
| Count all requests together              | Bots, errors and redirects distort the human figures |
| Discard bots and errors at counting time | Discarded traffic can no longer be queried           |

## Decision

Each request is assigned a class at counting time. The class combines its audience, human or bot, with its status group:
correct, error or other, such as a redirect. Every aggregate stores separate counters per class. A query sums the
classes selected by a filter on audience and status, over pages, files or both. The default filter is human audience
with correct status.

The counting rules, which assign a class and tell a page from a file, are outside the scope of this decision.

## Consequences

- Bot, error, page and file figures are available through a filter for every stored period.
- Storage grows with the number of classes present in each period.
- A change to the counting rules affects only requests counted after it: stored counters are not recomputed.
