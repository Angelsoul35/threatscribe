"""Load and (re)fetch the real CVE-severity corpus used for validation.

The corpus is a snapshot of the public Hugging Face dataset
``harinpurumandla/cve-severity-dataset`` (152,070 real CVEs, each with its NVD
description and the CVSS v3.1 vector string). A spread-out subset is vendored under
``datasets/`` so the benchmark and the tests run offline and reproducibly, while
:func:`fetch_cves` regenerates that subset from the dataset-server rows API
(``urllib`` + retries, no authentication).

Every record is ground truth: the ``vector`` field is the machine-readable
statement of what the CVE does, and the ``description`` is the free-text report
that :mod:`threatscribe` is built to structure.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.request import Request, urlopen

_ROWS_API = (
    "https://datasets-server.huggingface.co/rows"
    "?dataset=harinpurumandla%2Fcve-severity-dataset"
    "&config=default&split=train&offset={offset}&length={length}"
)

#: Total rows in the upstream ``train`` split (reported by the rows API).
TOTAL_ROWS = 152_070

#: Where the vendored subset lives, relative to the repository root.
DATASET_PATH = Path(__file__).resolve().parent.parent / "datasets" / "cve_severity_sample.jsonl"

_FIELDS = ("cve_id", "year", "description", "vector", "split")


@dataclass(frozen=True)
class CVERecord:
    """One real CVE: its id, year, free-text description and CVSS v3.1 vector."""

    cve_id: str
    year: int
    description: str
    vector: str
    split: str


def _fetch_page(offset: int, length: int, *, retries: int, backoff: float) -> list[dict]:
    """Fetch one page of rows, retrying with exponential backoff on failure."""
    url = _ROWS_API.format(offset=offset, length=length)
    last: Exception | None = None
    for attempt in range(retries):
        try:
            request = Request(url, headers={"User-Agent": "threatscribe-real-data/1.0"})
            with urlopen(request, timeout=60) as response:
                payload = json.load(response)
            return [row["row"] for row in payload["rows"]]
        except Exception as exc:  # network error, bad status, or malformed JSON
            last = exc
            if attempt + 1 < retries:
                time.sleep(backoff * (2**attempt))
    raise RuntimeError(f"failed to fetch rows at offset {offset} after {retries} tries: {last}")


def fetch_cves(
    total: int = 6_000,
    *,
    length: int = 100,
    stride: int | None = None,
    retries: int = 4,
    backoff: float = 0.5,
) -> list[CVERecord]:
    """Download a subset of real CVEs, spread across the dataset for year variety.

    Pages are read at evenly spaced offsets so the subset spans the full history
    of the corpus (CVEs from the late 1990s through the 2020s) rather than one
    vendor or one year. Duplicate ``cve_id`` values are dropped.
    """
    if stride is None:
        blocks = max(1, total // length)
        stride = max(length, TOTAL_ROWS // blocks)
    records: list[CVERecord] = []
    seen: set[str] = set()
    offset = 0
    while len(records) < total and offset < TOTAL_ROWS:
        for raw in _fetch_page(offset, length, retries=retries, backoff=backoff):
            cve_id = raw["cve_id"]
            if cve_id in seen:
                continue
            seen.add(cve_id)
            records.append(
                CVERecord(
                    cve_id=cve_id,
                    year=int(raw["year"]),
                    description=raw["description"] or "",
                    vector=raw["vector"],
                    split=raw["split"],
                )
            )
            if len(records) >= total:
                break
        offset += stride
    return records[:total]


def save_cves(records: Iterable[CVERecord], path: Path | str = DATASET_PATH) -> Path:
    """Write records to a JSONL file, one compact JSON object per line."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            row = {
                "cve_id": record.cve_id,
                "year": record.year,
                "description": record.description,
                "vector": record.vector,
                "split": record.split,
            }
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    return path


def load_cves(path: Path | str = DATASET_PATH) -> list[CVERecord]:
    """Load the vendored CVE corpus from a JSONL file."""
    path = Path(path)
    records: list[CVERecord] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            records.append(
                CVERecord(
                    cve_id=row["cve_id"],
                    year=int(row["year"]),
                    description=row["description"] or "",
                    vector=row["vector"],
                    split=row["split"],
                )
            )
    return records


def _bucket(cve_id: str, buckets: int) -> int:
    """Deterministic, stable bucket for a CVE id (independent of Python hashing)."""
    digest = hashlib.sha256(cve_id.encode("utf-8")).hexdigest()
    return int(digest, 16) % buckets


def partition(
    records: Sequence[CVERecord], *, test_fraction: float = 0.5, buckets: int = 10
) -> tuple[list[CVERecord], list[CVERecord]]:
    """Split records into a development set and a held-out test set.

    The split hashes the ``cve_id``, so it is reproducible and leakage-free: a CVE
    is always on the same side of the split, regardless of order or run.
    """
    cut = round(buckets * (1.0 - test_fraction))
    dev: list[CVERecord] = []
    test: list[CVERecord] = []
    for record in records:
        (dev if _bucket(record.cve_id, buckets) < cut else test).append(record)
    return dev, test


def kfold(records: Sequence[CVERecord], k: int = 5, *, salt: str = "") -> list[list[CVERecord]]:
    """Partition records into ``k`` reproducible folds by hashing the CVE id."""
    folds: list[list[CVERecord]] = [[] for _ in range(k)]
    for record in records:
        index = _bucket(salt + record.cve_id, k)
        folds[index].append(record)
    return folds
