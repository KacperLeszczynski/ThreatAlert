from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict

from threat_alerting.settings import Settings, get_settings


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    service: str
    environment: str
    version: str

    model_config = ConfigDict(frozen=True)


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved_settings = settings or get_settings()
    application = FastAPI(
        title=resolved_settings.app_name,
        version=resolved_settings.app_version,
    )
    application.state.settings = resolved_settings

    @application.get("/health", response_model=HealthResponse, tags=["system"])
    def health() -> HealthResponse:
        return HealthResponse(
            service=resolved_settings.app_name,
            environment=resolved_settings.app_env,
            version=resolved_settings.app_version,
        )

    return application


app = create_app()
