# ADR-0006: A key per year for the unique-visitor sketches

**Date:** 2026-11-15 **Status:** Accepted, supersedes in part [ADR-0004](0004-hyperloglog.md)

## Context

kirika is meant to count visitors without keeping who they were. A HyperLogLog sketch (ADR-0004) keeps bits of a hash of
each client, and with the library's own hash those bits depend on the address alone: the sketches stay tied to the
addresses that visited for as long as the store keeps them.

## Alternatives considered

| Option                                | Reason rejected                                                   |
|---------------------------------------|-------------------------------------------------------------------|
| A key per month                       | A year would count a client of several of its months once in each |
| A key in a file outside the store     | A backup copies it too, and losing it counts every client again   |
| The library's hash with a secret seed | It is not built to keep its seed secret                           |

## Decision

A sketch takes each client as an HMAC-SHA256 under a random key of its year, kept in the store, so the months and hosts
of a year still merge. A year closes, and its key is deleted, when the store counts a page dated in February of the next
year or later. A page of a closed year counts in all but the unique visitors: a new key would count its clients twice.

## Consequences

- Until a year closes, its sketches stay tied to the addresses through the key in the store: a copy of the store, such
  as a backup, needs the care its logs need.
- Unique visitors merge within a calendar year only.
- Logs are best read oldest first, so no year closes before its logs are read.
- A deleted key stays in the file until bbolt reuses its page.
- The HMAC adds about 3% to an ingest on a CPU without SHA-2 instructions, and nothing measurable with them (measured
  with Go 1.27.3, linux/arm64).
