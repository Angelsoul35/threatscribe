"""Validate threatscribe's deterministic engines on real CVE data.

This runs the project's own components on the vendored corpus of real CVEs and
checks their structured output against the ground-truth CVSS vectors:

* **CVSS scoring** -- :mod:`threatscribe.cvss` reproduces the canonical FIRST.org
  base scores exactly on reference vectors, then derives a severity band for every
  real vector in the corpus.
* **Impact recovery** -- the curated phrase map recovers the impact class from the
  free-text description; precision/recall/F1 are measured against the impact class
  implied by the real vector, on a held-out split, with a majority baseline, a
  k-fold stability check, and a scrambled-input control that collapses the signal.
* **Indicator extraction** -- :func:`threatscribe.ioc.extract` recovers the CVE
  identifiers embedded in real descriptions.

Run it with ``python -m threatscribe.real_benchmark``. It reads the vendored
snapshot only, so it needs no network.
"""

from __future__ import annotations

import random
import re
import statistics
from collections import Counter
from collections.abc import Sequence

from .cvss import (
    ImpactClass,
    base_score,
    classify_impact,
    impact_class,
    parse_vector,
    severity,
)
from .ioc import IOCType, extract
from .real_data import CVERecord, kfold, load_cves, partition

# Canonical CVSS v3.1 vectors with their published base scores (FIRST.org).
REFERENCE_VECTORS: dict[str, float] = {
    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": 7.5,
    "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
    "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
    "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N": 3.1,
}

IMPACT_CLASSES: tuple[ImpactClass, ...] = (
    ImpactClass.TOTAL,
    ImpactClass.DOS,
    ImpactClass.INFO,
    ImpactClass.OTHER,
)

_CVE_ID = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def _prf(
    y_true: Sequence[object], y_pred: Sequence[object], label: object
) -> tuple[float, float, float, int]:
    """Precision, recall, F1 and support for one label (one-vs-rest)."""
    tp = sum(1 for t, p in zip(y_true, y_pred, strict=True) if p == label and t == label)
    fp = sum(1 for t, p in zip(y_true, y_pred, strict=True) if p == label and t != label)
    fn = sum(1 for t, p in zip(y_true, y_pred, strict=True) if p != label and t == label)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    support = sum(1 for t in y_true if t == label)
    return precision, recall, f1, support


def _macro_f1(
    y_true: Sequence[object], y_pred: Sequence[object], labels: Sequence[object]
) -> float:
    return statistics.fmean(_prf(y_true, y_pred, label)[2] for label in labels)


def cvss_report(records: Sequence[CVERecord]) -> dict:
    """Check the scorer against reference vectors and derive severity for the corpus."""
    reference = {}
    all_match = True
    for vector_str, expected in REFERENCE_VECTORS.items():
        got = base_score(parse_vector(vector_str))
        reference[vector_str] = {"expected": expected, "got": got, "match": got == expected}
        all_match = all_match and got == expected

    severities: Counter[str] = Counter()
    scored = 0
    for record in records:
        vector = parse_vector(record.vector)
        severities[severity(base_score(vector)).value] += 1
        scored += 1
    return {
        "reference": reference,
        "reference_all_match": all_match,
        "scored": scored,
        "severity_distribution": dict(severities),
    }


def _majority_class(records: Sequence[CVERecord]) -> ImpactClass:
    counts = Counter(impact_class(parse_vector(r.vector)) for r in records)
    return counts.most_common(1)[0][0]


def _impact_eval(
    records: Sequence[CVERecord], fallback: ImpactClass, *, scramble_seed: int | None = None
) -> dict:
    """Evaluate impact recovery on ``records``; optionally scramble the input first."""
    rng = random.Random(scramble_seed) if scramble_seed is not None else None

    def read(description: str) -> str:
        if rng is None:
            return description
        tokens = description.split()
        rng.shuffle(tokens)
        return " ".join(tokens)

    y_true = [impact_class(parse_vector(r.vector)) for r in records]
    fired = [classify_impact(read(r.description)) for r in records]
    y_pred = [tag.impact if tag is not None else fallback for tag in fired]

    correct = sum(1 for t, p in zip(y_true, y_pred, strict=True) if t == p)
    accuracy = correct / len(records)
    baseline = sum(1 for t in y_true if t == fallback) / len(records)
    coverage = sum(1 for tag in fired if tag is not None) / len(records)
    covered = [(t, tag.impact) for t, tag in zip(y_true, fired, strict=True) if tag is not None]
    covered_precision = (
        sum(1 for t, p in covered if t == p) / len(covered) if covered else 0.0
    )
    per_class = {}
    for label in IMPACT_CLASSES:
        precision, recall, f1, support = _prf(y_true, y_pred, label)
        per_class[label.value] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": support,
        }
    return {
        "n": len(records),
        "accuracy": accuracy,
        "baseline": baseline,
        "macro_f1": _macro_f1(y_true, y_pred, IMPACT_CLASSES),
        "coverage": coverage,
        "covered_precision": covered_precision,
        "per_class": per_class,
    }


def impact_report(records: Sequence[CVERecord], *, scramble_seed: int = 1234) -> dict:
    """Full impact-recovery evaluation: dev, held-out test, k-fold and control."""
    dev, test = partition(records)
    fallback = _majority_class(dev)
    dev_eval = _impact_eval(dev, fallback)
    test_eval = _impact_eval(test, fallback)
    control = _impact_eval(test, fallback, scramble_seed=scramble_seed)

    folds = kfold(records, k=5)
    fold_acc: list[float] = []
    fold_macro: list[float] = []
    for i, fold in enumerate(folds):
        train = [r for j, other in enumerate(folds) if j != i for r in other]
        fold_fallback = _majority_class(train)
        result = _impact_eval(fold, fold_fallback)
        fold_acc.append(result["accuracy"])
        fold_macro.append(result["macro_f1"])

    return {
        "fallback_class": fallback.value,
        "dev": dev_eval,
        "test": test_eval,
        "control_scrambled": control,
        "train_test_gap": dev_eval["accuracy"] - test_eval["accuracy"],
        "cv": {
            "folds": len(folds),
            "accuracy_mean": statistics.fmean(fold_acc),
            "accuracy_stdev": statistics.pstdev(fold_acc),
            "macro_f1_mean": statistics.fmean(fold_macro),
            "macro_f1_stdev": statistics.pstdev(fold_macro),
        },
    }


def ioc_report(records: Sequence[CVERecord]) -> dict:
    """Check that the IOC extractor recovers CVE identifiers embedded in real prose."""
    tp = fp = fn = 0
    descriptions_with_ids = 0
    total_iocs = 0
    for record in records:
        truth = {m.upper() for m in _CVE_ID.findall(record.description)}
        extracted = extract(record.description)
        total_iocs += len(extracted)
        predicted = {ioc.value.upper() for ioc in extracted if ioc.type is IOCType.CVE}
        if truth:
            descriptions_with_ids += 1
        tp += len(truth & predicted)
        fp += len(predicted - truth)
        fn += len(truth - predicted)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "descriptions_with_cve_ids": descriptions_with_ids,
        "cve_true_positives": tp,
        "cve_false_positives": fp,
        "cve_false_negatives": fn,
        "cve_precision": precision,
        "cve_recall": recall,
        "cve_f1": f1,
        "total_iocs_extracted": total_iocs,
    }


def run(records: Sequence[CVERecord] | None = None) -> dict:
    """Run every validation and return a structured result."""
    records = list(records) if records is not None else load_cves()
    return {
        "records": len(records),
        "cvss": cvss_report(records),
        "impact": impact_report(records),
        "ioc": ioc_report(records),
    }


def _bar(fraction: float, width: int = 28) -> str:
    filled = round(fraction * width)
    return "#" * filled + "-" * (width - filled)


def format_report(result: dict) -> str:
    """Render the structured result as a readable text report."""
    lines: list[str] = []
    out = lines.append
    out("=" * 72)
    out("threatscribe -- validation on real CVE data")
    out("=" * 72)
    out(f"Corpus: {result['records']} real CVEs (NVD descriptions + CVSS v3.1 vectors)")
    out("")

    cvss = result["cvss"]
    out("1) CVSS v3.1 scoring engine")
    out("   Canonical reference vectors (vector -> base score):")
    for vector_str, info in cvss["reference"].items():
        flag = "OK" if info["match"] else "MISMATCH"
        out(f"     [{flag}] {vector_str}  got {info['got']:.1f} (expected {info['expected']:.1f})")
    out(f"   All reference scores reproduced exactly: {cvss['reference_all_match']}")
    out(f"   Derived severity over {cvss['scored']} real vectors:")
    total = max(cvss["scored"], 1)
    for band in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"):
        count = cvss["severity_distribution"].get(band, 0)
        out(f"     {band:8} {count:6d}  {_bar(count / total)}")
    out("")

    impact = result["impact"]
    test = impact["test"]
    dev = impact["dev"]
    control = impact["control_scrambled"]
    out("2) Impact-class recovery from description prose")
    out(
        f"   Held-out test set: {test['n']} CVEs  "
        f"(majority baseline class = {impact['fallback_class']})"
    )
    out(f"   Accuracy          {test['accuracy']:.3f}   (majority baseline {test['baseline']:.3f})")
    out(f"   Macro-F1          {test['macro_f1']:.3f}")
    out(f"   Coverage          {test['coverage']:.3f}   (fraction where a phrase fires)")
    out(f"   Covered-precision {test['covered_precision']:.3f}   (accuracy where a phrase fires)")
    out("   Per class (precision / recall / F1 / support):")
    for label in ("TOTAL", "DOS", "INFO", "OTHER"):
        stats = test["per_class"][label]
        out(
            f"     {label:6} P={stats['precision']:.3f} R={stats['recall']:.3f} "
            f"F1={stats['f1']:.3f} support={stats['support']}"
        )
    out(
        f"   Development accuracy {dev['accuracy']:.3f} -> train-test gap "
        f"{impact['train_test_gap']:+.3f} (small gap = generalises, not tuned to one split)"
    )
    cv = impact["cv"]
    out(
        f"   {cv['folds']}-fold stability: accuracy {cv['accuracy_mean']:.3f} "
        f"+/- {cv['accuracy_stdev']:.3f}, macro-F1 {cv['macro_f1_mean']:.3f} "
        f"+/- {cv['macro_f1_stdev']:.3f}"
    )
    out(
        f"   Scrambled-input control: accuracy {control['accuracy']:.3f} (-> ~baseline), "
        f"macro-F1 {control['macro_f1']:.3f} (collapses from {test['macro_f1']:.3f})"
    )
    out("")

    ioc = result["ioc"]
    out("3) Indicator extraction on real prose (ioc.extract)")
    out(f"   Descriptions embedding a CVE id: {ioc['descriptions_with_cve_ids']}")
    out(
        f"   CVE-id recovery: precision {ioc['cve_precision']:.3f}, "
        f"recall {ioc['cve_recall']:.3f}, F1 {ioc['cve_f1']:.3f}"
    )
    out(f"   Total IOCs extracted across the corpus: {ioc['total_iocs_extracted']}")
    out("=" * 72)
    return "\n".join(lines)


def main() -> None:
    print(format_report(run()))


if __name__ == "__main__":
    main()
