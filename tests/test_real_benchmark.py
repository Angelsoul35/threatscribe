"""Functional tests for the real-CVE validation.

These run threatscribe's own engines on the vendored corpus of real CVEs and
assert the validation holds: the loader returns the real data, the CVSS scorer
reproduces the canonical scores, impact recovery beats the majority baseline on a
held-out split and stays stable under cross-validation, a scrambled-input control
collapses the signal, the IOC extractor recovers embedded CVE ids, and the fetch
path parses and retries. Every assertion is load-bearing: break the thing it
checks and the test fails.
"""

from __future__ import annotations

import io
import json
import urllib.error

import pytest

from threatscribe import cvss, real_benchmark, real_data

EXPECTED_COUNT = 6000


@pytest.fixture(scope="module")
def corpus() -> list[real_data.CVERecord]:
    return real_data.load_cves()


@pytest.fixture(scope="module")
def result(corpus: list[real_data.CVERecord]) -> dict:
    return real_benchmark.run(corpus)


# --------------------------------------------------------------------------- #
# Loader returns the real data.
# --------------------------------------------------------------------------- #
def test_loader_returns_the_real_corpus(corpus: list[real_data.CVERecord]) -> None:
    assert len(corpus) == EXPECTED_COUNT
    ids = {record.cve_id for record in corpus}
    assert len(ids) == EXPECTED_COUNT  # no duplicates
    assert "CVE-2016-0002" in ids  # a known row from the real dataset
    # Real CVE ids, real multi-year span, and every vector is a valid CVSS v3.1 string.
    assert all(record.cve_id.startswith("CVE-") for record in corpus)
    assert len({record.year for record in corpus}) >= 3
    for record in corpus:
        vector = cvss.parse_vector(record.vector)  # raises on a malformed vector
        assert vector.attack_vector in "NALP"


# --------------------------------------------------------------------------- #
# CVSS scorer reproduces the canonical formula.
# --------------------------------------------------------------------------- #
def test_cvss_scorer_matches_reference_vectors() -> None:
    for vector_str, expected in real_benchmark.REFERENCE_VECTORS.items():
        assert cvss.base_score(cvss.parse_vector(vector_str)) == expected


def test_cvss_severity_bands() -> None:
    bands = {
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": cvss.Severity.CRITICAL,  # 9.8
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": cvss.Severity.HIGH,  # 7.5
        "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": cvss.Severity.MEDIUM,  # 6.1
        "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N": cvss.Severity.LOW,  # 3.1
        "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": cvss.Severity.NONE,  # 0.0
    }
    for vector_str, expected in bands.items():
        assert cvss.severity(cvss.base_score(cvss.parse_vector(vector_str))) is expected


def test_cvss_reports_all_reference_matches(result: dict) -> None:
    assert result["cvss"]["reference_all_match"] is True
    assert result["cvss"]["scored"] == EXPECTED_COUNT
    dist = result["cvss"]["severity_distribution"]
    # A real, varied corpus is dominated by HIGH/MEDIUM, not all one band.
    assert dist["CRITICAL"] > 0 and dist["HIGH"] > 0 and dist["MEDIUM"] > 0
    assert max(dist.values()) < result["cvss"]["scored"]


def test_parse_vector_rejects_malformed() -> None:
    with pytest.raises(ValueError):
        cvss.parse_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")  # missing A
    with pytest.raises(ValueError):
        cvss.parse_vector("AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")  # invalid AV
    with pytest.raises(ValueError):
        cvss.parse_vector("AV:N/AC/PR:N/UI:N/S:U/C:H/I:H/A:H")  # token without a colon


def test_parse_vector_accepts_prefix_and_trailing_slash() -> None:
    vector = cvss.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/")
    assert vector.attack_vector == "N"
    assert cvss.base_score(vector) == 9.8


# --------------------------------------------------------------------------- #
# Impact recovery beats the right baseline on held-out data.
# --------------------------------------------------------------------------- #
def test_impact_recovery_beats_baseline_on_held_out(result: dict) -> None:
    test = result["impact"]["test"]
    assert test["n"] > 1000  # a real held-out split, not a toy
    # The deterministic phrase map must clear the majority baseline by a real margin.
    assert test["accuracy"] - test["baseline"] >= 0.05
    assert test["macro_f1"] >= 0.35
    # Where a phrase fires, it is right far more often than the baseline rate.
    assert test["coverage"] >= 0.20
    assert test["covered_precision"] >= 0.65
    # Each signalled class is genuinely recovered.
    assert test["per_class"]["TOTAL"]["recall"] >= 0.70
    assert test["per_class"]["INFO"]["precision"] >= 0.60


def test_impact_recovery_generalises(result: dict) -> None:
    impact = result["impact"]
    # Tiny train-test gap: the rules are not tuned to one split.
    assert abs(impact["train_test_gap"]) <= 0.10
    cv = impact["cv"]
    assert cv["accuracy_mean"] >= 0.42
    assert cv["accuracy_stdev"] <= 0.05  # stable across folds


# --------------------------------------------------------------------------- #
# Scrambled-input control collapses the signal to the baseline.
# --------------------------------------------------------------------------- #
def test_scramble_control_collapses_the_signal(result: dict) -> None:
    test = result["impact"]["test"]
    control = result["impact"]["control_scrambled"]
    # Shuffling the words destroys the multi-word phrases, so the macro-F1 crashes
    # and accuracy falls back to roughly the majority baseline.
    assert control["macro_f1"] <= test["macro_f1"] - 0.10
    assert control["accuracy"] <= test["baseline"] + 0.03


# --------------------------------------------------------------------------- #
# IOC extractor recovers indicators from real prose.
# --------------------------------------------------------------------------- #
def test_ioc_extraction_on_real_prose(result: dict) -> None:
    ioc = result["ioc"]
    assert ioc["descriptions_with_cve_ids"] > 0
    assert ioc["cve_precision"] >= 0.98
    assert ioc["cve_recall"] >= 0.98
    assert ioc["cve_false_positives"] == 0
    assert ioc["total_iocs_extracted"] > 500


# --------------------------------------------------------------------------- #
# Impact tagging is evidence-carrying and abstains on silence.
# --------------------------------------------------------------------------- #
def test_classify_impact_tags_with_evidence() -> None:
    total = cvss.classify_impact("A remote attacker can execute arbitrary code on the host.")
    assert total is not None
    assert total.impact is cvss.ImpactClass.TOTAL
    assert total.evidence in "a remote attacker can execute arbitrary code on the host."

    info = cvss.classify_impact("The flaw allows an attacker to obtain sensitive information.")
    assert info is not None and info.impact is cvss.ImpactClass.INFO

    assert cvss.classify_impact("The quarterly meeting was rescheduled to Tuesday.") is None


def test_impact_class_from_vector() -> None:
    total = cvss.parse_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    dos = cvss.parse_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
    info = cvss.parse_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    other = cvss.parse_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N")
    assert cvss.impact_class(total) is cvss.ImpactClass.TOTAL
    assert cvss.impact_class(dos) is cvss.ImpactClass.DOS
    assert cvss.impact_class(info) is cvss.ImpactClass.INFO
    assert cvss.impact_class(other) is cvss.ImpactClass.OTHER


# --------------------------------------------------------------------------- #
# Fetch path: parsing, dedup and retry, all with a monkeypatched urlopen.
# --------------------------------------------------------------------------- #
def _page(rows: list[dict]) -> io.BytesIO:
    payload = {"rows": [{"row": row} for row in rows]}
    return io.BytesIO(json.dumps(payload).encode("utf-8"))


def _row(cve_id: str, year: int) -> dict:
    return {
        "cve_id": cve_id,
        "year": year,
        "description": f"{cve_id} allows remote code execution.",
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "split": "train",
    }


def test_fetch_cves_parses_and_dedups(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = [
        _page([_row("CVE-2021-0001", 2021), _row("CVE-2021-0002", 2021)]),
        _page([_row("CVE-2021-0002", 2021), _row("CVE-2021-0003", 2021)]),  # dup + new
    ]
    calls = {"n": 0}

    def fake_urlopen(request, timeout=0):
        page = pages[calls["n"]]
        calls["n"] += 1
        return page

    monkeypatch.setattr(real_data, "urlopen", fake_urlopen)
    records = real_data.fetch_cves(total=3, length=2, stride=2, backoff=0.0)
    assert [r.cve_id for r in records] == ["CVE-2021-0001", "CVE-2021-0002", "CVE-2021-0003"]
    assert all(isinstance(r, real_data.CVERecord) for r in records)
    assert records[0].year == 2021


def test_fetch_cves_retries_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = {"n": 0}

    def flaky_urlopen(request, timeout=0):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise urllib.error.URLError("transient network blip")
        return _page([_row("CVE-2022-1234", 2022)])

    monkeypatch.setattr(real_data, "urlopen", flaky_urlopen)
    records = real_data.fetch_cves(total=1, length=1, stride=1, retries=3, backoff=0.0)
    assert attempts["n"] == 2  # failed once, then succeeded
    assert records[0].cve_id == "CVE-2022-1234"


def test_fetch_cves_gives_up_after_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    def always_fail(request, timeout=0):
        raise urllib.error.URLError("down")

    monkeypatch.setattr(real_data, "urlopen", always_fail)
    with pytest.raises(RuntimeError):
        real_data.fetch_cves(total=1, length=1, stride=1, retries=2, backoff=0.0)


# --------------------------------------------------------------------------- #
# The readable report renders the real numbers.
# --------------------------------------------------------------------------- #
def test_format_report_renders_key_numbers(result: dict) -> None:
    text = real_benchmark.format_report(result)
    assert "validation on real CVE data" in text
    assert f"Corpus: {EXPECTED_COUNT}" in text
    assert "All reference scores reproduced exactly: True" in text
    assert "Impact-class recovery" in text
    assert "Scrambled-input control" in text
    assert "CVE-id recovery" in text


def test_main_prints_report(capsys: pytest.CaptureFixture[str]) -> None:
    real_benchmark.main()
    out = capsys.readouterr().out
    assert "CVSS v3.1 scoring engine" in out
    assert "Held-out test set" in out


def test_save_and_load_round_trip(tmp_path) -> None:
    records = [
        real_data.CVERecord(
            cve_id="CVE-2020-1111",
            year=2020,
            description="remote code execution",
            vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            split="train",
        ),
    ]
    path = tmp_path / "subset.jsonl"
    real_data.save_cves(records, path)
    loaded = real_data.load_cves(path)
    assert loaded == records
