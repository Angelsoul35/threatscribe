"""Summarize a threat report: LLM-assisted, with an extractive fallback.

An LLM writes a short analyst summary when a provider is reachable. Offline, a
deterministic extractive summariser selects the most salient sentences (by
position and by threat-vocabulary density), so a summary is always produced with
no network. The summary is a reading aid; the extracted IOCs and ATT&CK tags are
the structured, authoritative output.
"""

from __future__ import annotations

import re

from .llm.base import LLMClient, LLMError

_SYSTEM = (
    "You are a cyber threat-intelligence analyst. Summarise the report in two or "
    "three sentences: the threat actor or malware, what it targets, how it operates, "
    "and the key impact. Be concise and factual."
)

_SALIENT = (
    "ransomware", "malware", "campaign", "threat actor", "apt", "exploit",
    "vulnerability", "phishing", "command and control", "c2", "backdoor",
    "credential", "payload", "encrypt", "targets", "targeted",
)

_SENTENCE = re.compile(r"(?<=[.!?])\s+")


def extractive_summary(text: str, max_sentences: int = 3) -> str:
    sentences = [s.strip() for s in _SENTENCE.split(text.strip()) if s.strip()]
    if not sentences:
        return ""
    scored: list[tuple[float, int, str]] = []
    for i, sentence in enumerate(sentences):
        low = sentence.lower()
        score = sum(1 for kw in _SALIENT if kw in low)
        if i == 0:
            score += 1  # lead sentence bonus
        scored.append((score, i, sentence))
    top = sorted(scored, key=lambda t: (-t[0], t[1]))[:max_sentences]
    chosen = sorted(top, key=lambda t: t[1])  # restore reading order
    return " ".join(s for _, _, s in chosen)


class Summarizer:
    def __init__(self, llm: LLMClient | None = None, max_tokens: int = 220) -> None:
        self.llm = llm
        self.max_tokens = max_tokens

    def summarize(self, text: str) -> tuple[str, str]:
        if self.llm is not None and text.strip():
            try:
                result = self.llm.complete(_SYSTEM, text, max_tokens=self.max_tokens)
                summary = result.text.strip()
                if summary:
                    return summary, "llm"
            except LLMError:
                pass
        return extractive_summary(text), "extractive"
