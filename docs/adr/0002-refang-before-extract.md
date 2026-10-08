# ADR 0002: Refang before extracting

## Status

Accepted.

## Context

Threat reports deliberately *defang* indicators so a reader cannot accidentally
click or resolve them: `hxxps://evil[.]com`, `8[.]8[.]8[.]8`,
`user[at]evil[dot]com`. A naive extractor that runs its regexes over the raw text
misses all of these — exactly the indicators the report most wants to convey.

## Decision

**Refang first**: rewrite the common defang schemes (`hxxp`→`http`, `[.]`→`.`,
`[at]`→`@`, `[dot]`→`.`, `[:]`→`:`) to their real form, then run the extraction
regexes over the refanged text.

## Consequences

- **Defanged indicators are caught.** A defanged URL, IP, domain or email is
  extracted the same as a plain one.
- **Normalised output.** Indicators come out in canonical form, ready to feed a
  blocklist or a hunt, regardless of how the report styled them.
- **Simple and ordered.** Refang is a short, fixed list of substitutions applied
  once before extraction, so it is cheap and predictable.
- **Trade-off.** Refanging is heuristic — an exotic or novel defang scheme not in
  the list is not undone, and in theory refanging could alter benign text that
  happens to contain `[.]`. In practice the schemes are well-known and the risk is
  negligible; new schemes are one-line additions to the refang list.
