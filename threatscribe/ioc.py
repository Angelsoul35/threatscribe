"""Extract indicators of compromise (IOCs) from threat-report text.

Threat reports mix prose with indicators, often *defanged* so they are not
clickable — ``hxxp://evil[.]com``, ``8[.]8[.]8[.]8``. This module refangs the text
first, then extracts IPs, domains, URLs, file hashes, emails, CVEs and Bitcoin
addresses with precise regular expressions, deduplicating the results. Extraction
is deterministic, which is what IOC handling demands: the same report always
yields the same, auditable indicator set.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum


class IOCType(StrEnum):
    IPV4 = "ipv4"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    CVE = "cve"
    BTC = "btc"


@dataclass(frozen=True)
class IOC:
    type: IOCType
    value: str


# Common defang schemes, undone before extraction.
_REFANG = [
    (re.compile(r"h[xX]{2}p(s?)://"), r"http\1://"),
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\(\.\)"), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[at\]", re.I), "@"),
    (re.compile(r"\[dot\]", re.I), "."),
]


def refang(text: str) -> str:
    for pattern, repl in _REFANG:
        text = pattern.sub(repl, text)
    return text


_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_URL = re.compile(r"\bhttps?://[^\s<>\"'\])]+", re.I)
_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_BTC = re.compile(r"\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|co|ru|cn|info|biz|xyz|top|gov|edu|mil|de|uk|br|dev)\b"
)


def extract(text: str) -> list[IOC]:
    clean = refang(text)
    found: list[IOC] = []
    seen: set[tuple[str, str]] = set()

    def add(ioc_type: IOCType, value: str) -> None:
        key = (ioc_type.value, value.lower())
        if key not in seen:
            seen.add(key)
            found.append(IOC(ioc_type, value))

    # Hashes first (longest to shortest) so a SHA256 is not split into MD5s.
    for m in _SHA256.findall(clean):
        add(IOCType.SHA256, m)
    hashed = {v.lower() for _, v in seen}
    for m in _SHA1.findall(clean):
        if m.lower() not in hashed:
            add(IOCType.SHA1, m)
    for m in _MD5.findall(clean):
        if m.lower() not in {v for _, v in seen}:
            add(IOCType.MD5, m)

    for m in _CVE.findall(clean):
        add(IOCType.CVE, m.upper())
    for m in _URL.findall(clean):
        add(IOCType.URL, m.rstrip(".,);"))
    for m in _EMAIL.findall(clean):
        add(IOCType.EMAIL, m)
    for m in _IPV4.findall(clean):
        add(IOCType.IPV4, m)
    for m in _BTC.findall(clean):
        add(IOCType.BTC, m)

    # Domains last; skip those already captured inside a URL or email.
    captured = " ".join(i.value.lower() for i in found if i.type in (IOCType.URL, IOCType.EMAIL))
    for m in _DOMAIN.findall(clean):
        if m.lower() in captured:
            continue
        add(IOCType.DOMAIN, m)

    return found


def group(iocs: list[IOC]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for ioc in iocs:
        out.setdefault(ioc.type.value, []).append(ioc.value)
    return out
