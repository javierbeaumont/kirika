# ADR-0005: Server-Sent Events for live updates

**Date:** 2026-11-07 **Status:** Accepted

## Context

While `serve` follows a log, the open dashboards should show what its new lines count without being reloaded. The news
goes one way, from the server: a dashboard asks for its data through the JSON API. kirika runs behind a reverse proxy or
on its own, often on a small board, as one binary with no dependency it can do without.

## Alternatives considered

| Option          | Reason rejected                                                                  |
|-----------------|----------------------------------------------------------------------------------|
| Polling the API | Late by up to an interval, and every dashboard queries even when nothing changed |
| Long polling    | A request per update, and the server must keep what changes between two requests |
| WebSocket       | Two-way for one-way news, and a dependency: no server in the standard library    |

## Decision

Each open dashboard holds a Server-Sent Events stream. The server sends a bare notice over it after lines of the
followed log are counted. A stream starts with one, for a dashboard that reconnects. On each notice the dashboard
reloads its view through the API. The streams open at once are limited.

## Consequences

- A stream is a plain HTTP response: a proxy passes it if it does not buffer it.
- The browser's `EventSource` reconnects after a network error, but gives up for good on an answer other than 200, such
  as a proxy's error while kirika restarts or the refusal past the limit. The dashboard then reconnects by itself.
- Each notice makes every open dashboard query the store; the limit bounds that load.
- A stream never ends on its own: shutting the server down has to end the open ones.
- Over HTTP/1.1 a browser opens at most 6 connections to a server, and each live dashboard holds one; HTTP/2 lifts that
  cap.
- Events can carry data later, such as a live feed's lines, on the same stream.
