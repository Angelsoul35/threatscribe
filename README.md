# threatscribe

Turns a free-text threat-intelligence report into structured output: the
**indicators of compromise** it contains, the **MITRE ATT&CK techniques** it
describes, and a short **summary**. Indicator extraction and tagging are
deterministic (regex and a curated keyword map); only the summary uses an LLM,
and even that falls back to a deterministic extractive summary offline.

[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-blue)](.github/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## Why this split matters

Threat reports are prose written for humans, but a SOC needs the machine-readable
parts — the IPs, domains, hashes and CVEs to block and hunt for, and the
techniques to map to detections. Those extractions must be **exact and
reproducible**: an IOC feed that sometimes misses an indicator, or invents one, is
worse than useless. So extraction and tagging are rule-based and auditable; the
LLM is confined to the one task where fluency helps and a mistake is low-risk —
the human-readable summary — and it is never required to be present.

## What it extracts

**IOCs (`ioc.py`).** Reports routinely *defang* indicators so they are not
clickable (`hxxps://evil[.]com`, `8[.]8[.]8[.]8`, `user[at]evil[dot]com`).
threatscribe **refangs** the text first, then extracts with precise regexes:

| Type | Examples handled |
| ---- | ---------------- |
| IPv4, domain, URL | refanged and deduplicated; a domain already inside a URL/email is not re-listed |
| MD5 / SHA1 / SHA256 | length-aware, so a 64-hex SHA256 is never mis-split into MD5s |
| email, CVE, Bitcoin address | standard formats |

Extraction is order-careful (hashes longest-first, domains last) and
deduplicates case-insensitively, so the same report always yields the same IOC
set.

**ATT&CK techniques (`attack.py`).** A curated map from phrases that appear in
reports ("spear-phishing", "powershell", "scheduled task", "ransomware",
"command and control", "public-facing") to the technique they describe. Each tag
carries the exact phrase that triggered it. It is a **lookup, not a classifier**:
the mapping is auditable and analyst-extensible, and a first-pass aid, not a
replacement for analyst mapping.

**Summary (`summarize.py`).** An LLM (via the provider cascade) writes a two-to-
three-sentence analyst summary. Offline, an extractive summariser selects the most
salient sentences by position and threat-vocabulary density. Each summary records
its `source` (`llm` or `extractive`).

## Validated on real CVE data

threatscribe's deterministic engines are validated on **6,000 real CVEs** (years
2016–2023) from the public Hugging Face dataset
[`harinpurumandla/cve-severity-dataset`](https://huggingface.co/datasets/harinpurumandla/cve-severity-dataset)
— each a real NVD description paired with its ground-truth CVSS v3.1 vector. A
snapshot is vendored under `datasets/`; run the full report offline with:

```bash
python -m threatscribe.real_benchmark
```

**CVSS v3.1 scoring (`cvss.py`).** A new deterministic engine parses the CVSS
vector a report cites and computes the base score with the exact FIRST.org v3.1
formula, then the qualitative severity. It reproduces the canonical reference
scores **exactly** (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → 9.8, `…C:H/I:N/A:N`
→ 7.5, `…UI:R/S:C/C:L/I:L/A:N` → 6.1, POODLE → 3.1) and derives a severity band
for all 6,000 vectors (785 CRITICAL, 2,448 HIGH, 2,499 MEDIUM, 268 LOW).

**Impact recovery from prose.** A curated phrase map — the same auditable,
evidence-carrying approach as the ATT&CK tagger — reads the formulaic NVD wording
(`execute arbitrary code`, `denial of service`, `obtain sensitive information`)
and recovers the primary impact class, validated against the class implied by the
real vector's confidentiality/integrity/availability triad. On a **held-out**
split (3,012 CVEs, leakage-free by hashing the CVE id):

| Metric | Result | Baseline / control |
| ------ | ------ | ------------------ |
| Accuracy | **0.487** | majority baseline 0.376 |
| Macro-F1 | **0.414** | scrambled-input control 0.173 |
| Covered-precision (where a phrase fires) | **0.782** | — |
| `TOTAL` recall / `INFO` precision | 0.893 / 0.764 | — |

The signal **generalises**: the development set scores 0.451 (a train–test gap of
only −0.036), and 5-fold accuracy is 0.469 ± 0.018. A **scrambled-input control**
— shuffling each description's words to destroy the phrases while keeping the
vocabulary — collapses accuracy to 0.387 (≈ the baseline) and macro-F1 from 0.414
to 0.173, confirming the signal lives in the wording, not an artifact.

**Indicator extraction on real reports.** Run on the real descriptions,
`ioc.extract` recovers every embedded CVE identifier with **precision and recall
of 1.000** and extracts 1,131 indicators across the corpus with no false
positives — the exact, reproducible behaviour an IOC feed requires.

**How to extend.** Impact recovery abstains on wording it does not list (coverage
0.371), which is a visible gap, not a silent error: broaden the phrase map, or add
per-metric extractors for attack vector and user interaction, to raise coverage
while the scramble control keeps the signal verifiable. See
`docs/estudio/04-validacion-datos-reales.md` for the full method, formulas and a
worked example.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

python -m threatscribe.cli demo                    # analyse a sample report, offline
python -m threatscribe.cli analyze report.txt      # analyse your own report
uvicorn threatscribe.main:app --reload             # HTTP API
```

```bash
curl -s -X POST localhost:8000/analyze -H 'content-type: application/json' \
  -d '{"text": "FIN-Example phished banks and ran hxxps://evil[.]com/x ..."}'
```

## Configuration

| Variable            | Default                                   | Meaning                     |
| ------------------- | ----------------------------------------- | --------------------------- |
| `TS_LLM_SPEC`       | `anthropic,openai,gemini,deepseek,ollama` | Provider cascade for summaries |
| `TS_LLM_MAX_TOKENS` | `220`                                     | Max tokens per summary      |

Provider keys come from their own environment variables; with none set, the
extractive summary is used and extraction/tagging are unaffected (they never use
an LLM).

## Testing

```bash
ruff check threatscribe tests
pytest --cov=threatscribe --cov-report=term-missing --cov-fail-under=80
```

Covers refang/extraction (every IOC type, the SHA256-not-split-into-MD5 case, the
domain-inside-URL case, dedup), ATT&CK tagging (evidence present, no false tags on
benign text), summarisation (extractive salience, LLM path, fallback), the
service, the HTTP API, and the CLI. Nothing in the tests touches a network.

## Documentation

- `docs/architecture.md` — extraction, tagging, summarisation, and the data flow.
- `docs/adr/` — the main design decisions and their trade-offs.
- `docs/estudio/` — a study guide in Spanish, including the real-data validation.
- `threatscribe/real_data.py` / `threatscribe/real_benchmark.py` — the real-CVE
  loader/fetcher and the validation report (`python -m threatscribe.real_benchmark`).
- `datasets/README.md` — provenance for the vendored real-CVE corpus.

## License

[MIT](LICENSE) © Angelo David Padilla Romero
