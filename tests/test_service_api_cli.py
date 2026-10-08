from __future__ import annotations

from fastapi.testclient import TestClient

from threatscribe import cli
from threatscribe.llm.fake import FailingLLM
from threatscribe.samples import SAMPLE_REPORT
from threatscribe.service import ThreatScribeService


def _service() -> ThreatScribeService:
    return ThreatScribeService(llm=FailingLLM())  # offline -> extractive summary


def test_service_analyze():
    result = _service().analyze(SAMPLE_REPORT)
    assert result["summary_source"] == "extractive"
    assert result["ioc_count"] >= 5
    assert "sha256" in result["iocs"]
    assert any(t["id"] == "T1566" for t in result["techniques"])


def test_api():
    import threatscribe.main as main

    main._service = _service()
    client = TestClient(main.app)
    assert client.get("/health").json() == {"status": "ok"}

    resp = client.post("/analyze", json={"text": SAMPLE_REPORT})
    assert resp.status_code == 200
    assert resp.json()["ioc_count"] >= 5

    assert client.post("/analyze", json={"text": ""}).status_code == 422


def test_cli_demo(capsys):
    cli.demo()
    out = capsys.readouterr().out
    assert "IOCs" in out
    assert "ATT&CK techniques" in out
    assert "CVE-2024-3400" in out


def test_cli_analyze_file(tmp_path, capsys):
    p = tmp_path / "report.txt"
    p.write_text(SAMPLE_REPORT, encoding="utf-8")
    cli.analyze_file(str(p))
    assert "IOCs" in capsys.readouterr().out


def test_cli_main_dispatch(monkeypatch):
    called = {"demo": False}
    monkeypatch.setattr(cli, "demo", lambda: called.__setitem__("demo", True))
    monkeypatch.setattr("sys.argv", ["threatscribe", "demo"])
    cli.main()
    assert called["demo"] is True
