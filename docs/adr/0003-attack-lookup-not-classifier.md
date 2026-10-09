# ADR 0003: ATT&CK tagging as a keyword lookup, not a classifier

## Status

Accepted.

## Context

Mapping a report to MITRE ATT&CK techniques could be a text-classification
problem. But a learned classifier would be opaque (an analyst could not see why a
technique was tagged), would need a labelled training set that does not exist in a
stable, agreed form, and could tag techniques with no basis in the text.

## Decision

Tag with a **curated keyword map**: phrases that appear in reports → the technique
they describe. Every tag records the exact phrase that triggered it. The result is
presented as a **first-pass aid**, not an authoritative mapping.

## Consequences

- **Transparent and auditable.** Each tag points to a phrase in the text; an
  analyst sees exactly why it was applied and can reject it.
- **No training data needed, easy to extend.** Adding coverage is adding a phrase,
  reviewed by a human, not retraining a model.
- **Grounded in its role.** Every tag is backed by a phrase in the text, so the
  tool is verifiable: it speeds up the analyst's mapping without overstating it.
- **Trade-off.** A keyword map misses techniques described in wording it does not
  list, and can over-tag on an ambiguous phrase. Both are visible (a tag shows its
  evidence; a missing tag is a gap to fill with a phrase), which is preferable to
  an opaque model's confident-but-unexplained output.
