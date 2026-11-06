# ADR-0004: HyperLogLog for unique visitors

**Date:** 2026-11-06 **Status:** Accepted

## Context

Unique visitors are the distinct clients that requested at least one page in a period. Counting them exactly means
keeping every client address of the period. A year must count once a visitor of several of its months, and a set of
hosts a visitor of several hosts. The count must also answer each traffic filter of ADR-0003, such as humans only.

## Alternatives considered

| Option                             | Reason rejected                                                                |
|------------------------------------|--------------------------------------------------------------------------------|
| Every client address of the period | Personal data on disk, growing with the traffic                                |
| A salted hash of every address     | One entry per visitor still; with the salt, IPv4 addresses fall to brute force |
| Unique counts per day or month     | Not additive: a visitor of several days, months or hosts counts once in each   |
| One sketch per host and month      | A sketch cannot be split, so it cannot answer a filter such as humans only     |

## Decision

A HyperLogLog sketch per host, month and traffic class, from `github.com/axiomhq/hyperloglog`: 2^12 registers, a
standard error of about 1.6%. Sketches merge, so a year is the union of its months, a set of hosts the union of theirs
and a filter the union of its classes. The version is v0.3.0 or later, whose decoder neither shares memory with its
input nor accepts a malformed sketch.

## Consequences

- No client address reaches the disk: a sketch holds bits of address hashes.
- The counts are estimates.
- A sketch takes at most about 4 KB, for each host, month and class with traffic.
- There is no unique count per day.
- The binary grows by about 49 KB (measured with Go 1.27.3, linux/arm64), with two indirect dependencies,
  `dgryski/go-metro` and `kamstrup/intmap`.
