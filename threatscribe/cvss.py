"""Deterministic CVSS v3.1 engine and impact-class tagging.

Threat reports cite CVEs, and the CVSS vector is the structured, machine-readable
statement of what a CVE does -- its attack vector, complexity, required
privileges, the need for user interaction, scope change and the
confidentiality/integrity/availability impact. This module:

* parses a CVSS v3.1 vector string into its eight base metrics (:func:`parse_vector`);
* computes the base score with the exact FIRST.org v3.1 formula (:func:`base_score`)
  and maps it to a qualitative severity band (:func:`severity`);
* derives a coarse impact class from the vector (:func:`impact_class`); and
* recovers that impact class from report prose with a curated phrase map
  (:func:`classify_impact`) -- the same auditable, evidence-carrying approach as the
  ATT&CK tagger, reusing the IOC module's :func:`~threatscribe.ioc.refang`.

Everything here is deterministic: the same vector always yields the same score,
and the same report always yields the same impact tag, each traceable to the rule
that produced it.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum

from .ioc import refang


class Severity(StrEnum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ImpactClass(StrEnum):
    TOTAL = "TOTAL"  # complete loss of confidentiality, integrity and availability
    DOS = "DOS"  # availability-only impact (denial of service)
    INFO = "INFO"  # confidentiality-only impact (information disclosure)
    OTHER = "OTHER"  # any other / mixed impact profile


@dataclass(frozen=True)
class CVSSVector:
    """The eight CVSS v3.1 base metrics, as single-letter codes."""

    attack_vector: str  # AV: N(etwork) A(djacent) L(ocal) P(hysical)
    attack_complexity: str  # AC: L(ow) H(igh)
    privileges_required: str  # PR: N(one) L(ow) H(igh)
    user_interaction: str  # UI: N(one) R(equired)
    scope: str  # S: U(nchanged) C(hanged)
    confidentiality: str  # C: N(one) L(ow) H(igh)
    integrity: str  # I: N(one) L(ow) H(igh)
    availability: str  # A: N(one) L(ow) H(igh)
    raw: str = ""


_ALLOWED: dict[str, frozenset[str]] = {
    "AV": frozenset("NALP"),
    "AC": frozenset("LH"),
    "PR": frozenset("NLH"),
    "UI": frozenset("NR"),
    "S": frozenset("UC"),
    "C": frozenset("NLH"),
    "I": frozenset("NLH"),
    "A": frozenset("NLH"),
}
_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def parse_vector(vector: str) -> CVSSVector:
    """Parse a CVSS v3.1 base vector such as ``AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H``.

    An optional ``CVSS:3.1/`` prefix is accepted. Raises :class:`ValueError` when a
    required metric is missing or carries a value outside the v3.1 specification.
    """
    text = vector.strip()
    if text.upper().startswith("CVSS:"):
        _, _, text = text.partition("/")
    metrics: dict[str, str] = {}
    for token in text.split("/"):
        if not token:
            continue
        if ":" not in token:
            raise ValueError(f"malformed metric {token!r} in vector {vector!r}")
        key, _, value = token.partition(":")
        metrics[key.strip().upper()] = value.strip().upper()
    for name in _ORDER:
        if name not in metrics:
            raise ValueError(f"missing base metric {name} in vector {vector!r}")
        if metrics[name] not in _ALLOWED[name]:
            raise ValueError(f"invalid {name} value {metrics[name]!r} in vector {vector!r}")
    return CVSSVector(
        attack_vector=metrics["AV"],
        attack_complexity=metrics["AC"],
        privileges_required=metrics["PR"],
        user_interaction=metrics["UI"],
        scope=metrics["S"],
        confidentiality=metrics["C"],
        integrity=metrics["I"],
        availability=metrics["A"],
        raw=vector,
    )


# FIRST.org CVSS v3.1 metric weights.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: round up to one decimal place, avoiding float error."""
    scaled = round(value * 100_000)
    if scaled % 10_000 == 0:
        return scaled / 100_000.0
    return (math.floor(scaled / 10_000) + 1) / 10.0


def base_score(vector: CVSSVector) -> float:
    """Compute the CVSS v3.1 base score (0.0-10.0) with the exact FIRST.org formula."""
    iss = 1.0 - (
        (1.0 - _CIA[vector.confidentiality])
        * (1.0 - _CIA[vector.integrity])
        * (1.0 - _CIA[vector.availability])
    )
    if vector.scope == "U":
        impact = 6.42 * iss
        pr = _PR_UNCHANGED[vector.privileges_required]
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        pr = _PR_CHANGED[vector.privileges_required]
    if impact <= 0.0:
        return 0.0
    exploitability = (
        8.22
        * _AV[vector.attack_vector]
        * _AC[vector.attack_complexity]
        * pr
        * _UI[vector.user_interaction]
    )
    combined = impact + exploitability
    if vector.scope == "C":
        combined *= 1.08
    return _roundup(min(combined, 10.0))


def severity(score: float) -> Severity:
    """Map a base score to its CVSS v3.1 qualitative severity band."""
    if score <= 0.0:
        return Severity.NONE
    if score < 4.0:
        return Severity.LOW
    if score < 7.0:
        return Severity.MEDIUM
    if score < 9.0:
        return Severity.HIGH
    return Severity.CRITICAL


def impact_class(vector: CVSSVector) -> ImpactClass:
    """The ground-truth impact class implied by the vector's C/I/A triad."""
    c, i, a = vector.confidentiality, vector.integrity, vector.availability
    if c == "H" and i == "H" and a == "H":
        return ImpactClass.TOTAL
    if a != "N" and c == "N" and i == "N":
        return ImpactClass.DOS
    if c != "N" and i == "N" and a == "N":
        return ImpactClass.INFO
    return ImpactClass.OTHER


# Curated phrase -> impact-class map, ordered so the most specific effect wins.
# These are the formulaic effect phrases that recur across NVD descriptions; each
# tag records the exact phrase that triggered it, exactly like the ATT&CK tagger.
_IMPACT_RULES: tuple[tuple[ImpactClass, tuple[str, ...]], ...] = (
    (
        ImpactClass.DOS,
        (
            "denial of service",
            "cause a crash",
            "causes a crash",
            "cause the application to crash",
            "reboot",
            "resource exhaustion",
            "infinite loop",
            "null pointer dereference",
            "segmentation fault",
            "application crash",
            "consume memory",
            "consume cpu",
            "memory consumption",
            "unresponsive",
            "out of memory",
            "stack exhaustion",
        ),
    ),
    (
        ImpactClass.INFO,
        (
            "obtain sensitive information",
            "sensitive information",
            "information disclosure",
            "obtain information",
            "read arbitrary file",
            "disclose ",
            "information leak",
            "expose sensitive",
            "read sensitive",
            "access sensitive",
            "obtain credentials",
            "memory disclosure",
            "read memory contents",
            "exposure of sensitive",
        ),
    ),
    (
        ImpactClass.TOTAL,
        (
            "execute arbitrary code",
            "arbitrary code execution",
            "remote code execution",
            "code execution",
            "gain privileges",
            "gain root",
            "escalate privilege",
            "privilege escalation",
            "execute arbitrary commands",
            "execute commands",
            "arbitrary command execution",
            "command injection",
            "gain administrative",
            "unrestricted upload of",
            "insecure deserialization",
            "deserialization of untrusted",
        ),
    ),
)


@dataclass(frozen=True)
class ImpactTag:
    """An impact class recovered from prose, with the phrase that triggered it."""

    impact: ImpactClass
    evidence: str


def classify_impact(text: str) -> ImpactTag | None:
    """Recover the primary impact class from report prose, or ``None`` if unstated.

    The text is refanged (so defanged reports are read the same way) and matched
    against the curated phrase map. Returning ``None`` is deliberate: the engine
    abstains rather than guessing when no known effect phrase is present.
    """
    low = refang(text).lower()
    for impact, phrases in _IMPACT_RULES:
        for phrase in phrases:
            if phrase in low:
                return ImpactTag(impact, phrase)
    return None
