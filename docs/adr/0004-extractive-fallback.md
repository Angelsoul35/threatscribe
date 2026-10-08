# ADR 0004: An extractive fallback for the summary

## Status

Accepted.

## Context

The summary is the one LLM-assisted output. But the tool must run offline (in
tests, in an air-gapped SOC, when a provider is down) and must never fail to
produce a result just because the summary step cannot reach a model.

## Decision

Give the summariser a **deterministic extractive fallback**: when no provider is
reachable, select the most salient sentences from the report — scored by a
lead-sentence bonus and by threat-vocabulary density — and return those. Each
summary records whether it came from the LLM or the extractive path.

## Consequences

- **Always produces a summary.** The pipeline runs end to end with no network, so
  CI, the demo and an offline SOC all work.
- **Transparent source.** The `source` field says whether the summary was written
  by a model or extracted, so a reader calibrates trust accordingly.
- **Good enough offline.** Extractive summaries are less fluent than an LLM's but
  surface the salient sentences faithfully — and the IOCs and tags, which are the
  authoritative output, are unaffected either way.
- **Trade-off.** An extractive summary can read choppily and cannot paraphrase or
  infer. Acceptable: the summary is a convenience, not the product, and the
  structured extraction carries the real information.
