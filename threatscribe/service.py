"""Orchestrate IOC extraction, ATT&CK tagging and summarization."""

from __future__ import annotations

from .attack import tag
from .config import Settings, get_settings
from .ioc import extract, group
from .llm.base import LLMClient
from .llm.factory import build_llm
from .summarize import Summarizer


class ThreatScribeService:
    def __init__(
        self,
        settings: Settings | None = None,
        llm: LLMClient | None = None,
        summarizer: Summarizer | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.llm = llm if llm is not None else build_llm(self.settings.llm_spec)
        self.summarizer = summarizer or Summarizer(
            llm=self.llm, max_tokens=self.settings.llm_max_tokens
        )

    def analyze(self, text: str) -> dict:
        iocs = extract(text)
        techniques = tag(text)
        summary, source = self.summarizer.summarize(text)
        return {
            "summary": summary,
            "summary_source": source,
            "ioc_count": len(iocs),
            "iocs": group(iocs),
            "techniques": [
                {"id": t.technique_id, "name": t.name, "evidence": t.evidence} for t in techniques
            ],
        }
