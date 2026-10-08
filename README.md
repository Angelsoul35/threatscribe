# threatscribe

Turns a free-text threat-intelligence report into structured output: the
**indicators of compromise** it contains, the **MITRE ATT&CK techniques** it
describes, and a short **summary**. Indicator extraction and tagging are
deterministic (regex and a curated keyword map); only the summary uses an LLM,
and even that falls back to a deterministic extractive summary offline.

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
- `docs/estudio/` — a study guide in Spanish.

## License

MIT. See [LICENSE](LICENSE).
