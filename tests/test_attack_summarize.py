from __future__ import annotations

from threatscribe.attack import tag
from threatscribe.llm.fake import FailingLLM, FakeLLM
from threatscribe.summarize import Summarizer, extractive_summary


def test_tag_finds_techniques_with_evidence():
    text = "The actor used a phishing email and ran a PowerShell downloader, then ransomware."
    tags = {t.technique_id for t in tag(text)}
    assert "T1566" in tags  # phishing
    assert "T1059.001" in tags  # powershell
    assert "T1486" in tags  # ransomware
    assert all(t.evidence for t in tag(text))


def test_tag_empty_on_benign_text():
    assert tag("The weather was pleasant and the meeting went well.") == []


def test_extractive_summary_prefers_salient_sentences():
    text = (
        "The office opened at nine. A ransomware campaign targeted hospitals. "
        "Lunch was served. The malware encrypts files and demands payment."
    )
    summary = extractive_summary(text, max_sentences=2)
    assert "ransomware" in summary.lower()
    assert "lunch" not in summary.lower()


def test_summarizer_llm_path():
    s = Summarizer(llm=FakeLLM("A ransomware crew phished banks."))
    text, source = s.summarize("some report text")
    assert source == "llm"
    assert "ransomware" in text


def test_summarizer_fallback():
    s = Summarizer(llm=FailingLLM())
    text, source = s.summarize("A phishing campaign deployed malware against banks.")
    assert source == "extractive"
    assert text
