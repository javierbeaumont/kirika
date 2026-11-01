# ADR-0001: A substring heuristic to classify user agents

**Date:** 2026-11-01 **Status:** Accepted

## Context

kirika splits traffic into bot, desktop and mobile clients by the User-Agent header. That coarse split is all the
dashboard shows; browsers, operating systems and named robots come later. A third-party dependency must earn its place
and be versioned, so that each update is a reviewable step.

## Alternatives considered

| Option                         | Reason rejected                                                              |
|--------------------------------|------------------------------------------------------------------------------|
| `ua-parser/uap-go`             | No tags, only commit pins; its data, `uap-core`, was last tagged in May 2023 |
| `medama-io/go-useragent`       | Browser, OS and device detail that the split does not use                    |
| `matomo-org/device-detector`   | No Go parser                                                                 |
| Hand-written browser/OS tables | Too large to maintain for a split that needs a few markers                   |

## Decision

A substring heuristic for now, and a maintained library once kirika shows browsers, operating systems or named robots.
The ADR that picks the library supersedes this one and decides whether the markers stay as a fallback.

`internal/uaclass` lowercases the string and looks for substring markers: bot markers first, as crawlers can announce a
phone, then mobile ones. Anything else, an empty string included, is desktop. The marker lists live in the package.

## Consequences

- No dependency to update or audit.
- A heuristic: a client whose User-Agent has no marker, or hides what it is, is misclassified until a marker is added.
