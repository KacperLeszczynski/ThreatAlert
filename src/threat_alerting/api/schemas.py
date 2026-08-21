from typing import Any, Literal

from pydantic import BaseModel, ConfigDict


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    service: str
    environment: str
    version: str
    database: Literal["ok"] = "ok"

    model_config = ConfigDict(frozen=True)


class IngestionRunRequest(BaseModel):
    fixture: str | None = None

    model_config = ConfigDict(extra="forbid", frozen=True)


class DecisionCertificateResponse(BaseModel):
    alert_id: int
    profile: dict[str, Any]
    event: dict[str, Any]
    assessment: dict[str, Any]
    decision: dict[str, Any]

    model_config = ConfigDict(extra="forbid", frozen=True)
