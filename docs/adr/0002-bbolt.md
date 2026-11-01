# ADR-0002: bbolt as the store

**Date:** 2026-11-01 **Status:** Accepted

## Context

To analyse access logs beyond their rotation, kirika keeps what it derives from them. It must run on limited, slow
hardware: little RAM and flash storage that wears with every write. New lines arrive in small batches; reads ask for
ranges of time. The engine must be pure Go, so the binary cross-compiles statically; update data in place, without
background rewrites; keep keys ordered for range scans; and let kirika decide when to fsync.

## Alternatives considered

| Option               | Reason rejected                                                               |
|----------------------|-------------------------------------------------------------------------------|
| Flat JSON files      | Every update rewrites the whole file                                          |
| `modernc.org/sqlite` | Several MB more binary for a SQL engine that ordered key access does not need |
| `mattn/go-sqlite3`   | CGo: no static cross-compilation                                              |
| badger, pebble       | LSM trees: compaction rewrites and more RAM                                   |
| pogreb               | Hash-based: no range scans                                                    |
| BuntDB               | Keeps the whole dataset in RAM; shrinking its append-only file rewrites it    |

## Decision

`go.etcd.io/bbolt`: an ordered, pure-Go B+tree in one memory-mapped file, with ACID transactions. A write transaction
syncs to disk on commit, and kirika commits once per batch of lines.

## Consequences

- One file holds all the data: copying it while kirika is stopped is the backup.
- One process at a time: bbolt locks the file, and a second one fails when the open timeout runs out, so reads and
  writes share one process.
- The binary grows by about 448 KB (measured on the MVP, Go 1.26).
