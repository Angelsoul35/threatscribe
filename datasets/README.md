# Vendored dataset: real CVE severity corpus

`cve_severity_sample.jsonl` is a 6,000-record snapshot of real CVEs, used to
validate threatscribe's deterministic engines on real inputs (see
`threatscribe/real_benchmark.py`).

## Source

- **Dataset:** [`harinpurumandla/cve-severity-dataset`](https://huggingface.co/datasets/harinpurumandla/cve-severity-dataset)
  on the Hugging Face Hub (152,070 CVEs in the upstream `train` split).
- **Access:** the public datasets-server rows API, no authentication:
  `https://datasets-server.huggingface.co/rows?dataset=harinpurumandla%2Fcve-severity-dataset&config=default&split=train&offset=N&length=100`
- **Content:** each record is a real NVD CVE — its `cve_id`, `year`, free-text
  `description`, the CVSS v3.1 base `vector` string (e.g.
  `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H`) and the upstream `split` label.

The underlying CVE records are public data published by MITRE/NVD. This snapshot
redistributes a subset for reproducible evaluation; it is not an official feed.
Consult the upstream dataset card for its license and terms before any other use.

## What was selected

The snapshot reads pages at evenly spaced offsets across the whole dataset, so it
spans many years and many vendors rather than one slice. Duplicate `cve_id`
values are dropped. The file is ~2.9 MB of JSONL (one compact JSON object per
line) with the five fields above.

## How to regenerate

```bash
python -c "from threatscribe.real_data import fetch_cves, save_cves; save_cves(fetch_cves(6000))"
```

`fetch_cves` uses `urllib` with retries and exponential backoff. The vendored
snapshot lets the benchmark and the tests run fully offline; regeneration is only
needed to refresh or resize the corpus.
