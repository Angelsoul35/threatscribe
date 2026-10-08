# ADR 0001: Deterministic extraction, LLM only for the summary

## Status

Accepted.

## Context

A threat report is prose, but a SOC consumes its machine-readable parts: the IOCs
to block and hunt, and the techniques to map to detections. These have a hard
requirement — exactness and reproducibility. An IOC feed that sometimes misses a
real indicator leaves blind spots; one that invents indicators wastes hunts and
can cause wrongful blocks. An LLM, being probabilistic, can do both.

## Decision

Extract IOCs and tag ATT&CK techniques with **rules** (regexes and a curated
keyword map), deterministically. Use the **LLM only for the summary**, the one
output where fluency helps and an error is low-stakes because a human reads it —
and even there, fall back to an extractive summary when no provider is reachable.

## Consequences

- **Reproducible, auditable indicators.** The same report always yields the same
  IOCs and tags, each traceable to the text that produced it.
- **No hallucinated indicators.** A regex cannot invent an IP that is not in the
  text; an LLM might.
- **Offline-capable.** Extraction and tagging never need a network; the summary
  degrades gracefully.
- **Trade-off.** Rules only catch indicator formats and phrases they encode, and
  will miss a novel obfuscation or an unusual phrasing. That is the right failure
  mode for a feed — a missed indicator is a known gap to close with a new rule,
  whereas a hallucinated one is a silent, trust-destroying error. New formats are
  added as reviewed rules.
