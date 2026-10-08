"""threatscribe HTTP API."""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel, Field

from .service import ThreatScribeService

app = FastAPI(
    title="threatscribe",
    version="1.0.0",
    summary="Extract IOCs, tag ATT&CK techniques, and summarize threat reports.",
)

_service: ThreatScribeService | None = None


def get_service() -> ThreatScribeService:
    global _service
    if _service is None:
        _service = ThreatScribeService()
    return _service


class ReportRequest(BaseModel):
    text: str = Field(min_length=1)


@app.get("/health", tags=["ops"])
def health() -> dict:
    return {"status": "ok"}


@app.post("/analyze", tags=["intel"])
def analyze(request: ReportRequest) -> dict:
    return get_service().analyze(request.text)
