from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from threat_alerting.api import router
from threat_alerting.api.schemas import HealthResponse
from threat_alerting.bootstrap import ApplicationContainer, build_container
from threat_alerting.observability import configure_application_logging
from threat_alerting.settings import Settings, get_settings


def create_app(
    settings: Settings | None = None,
    *,
    container: ApplicationContainer | None = None,
) -> FastAPI:
    resolved_settings = settings or (container.settings if container else get_settings())
    configure_application_logging(resolved_settings.log_level)
    owns_container = container is None
    resolved_container = container or build_container(resolved_settings)

    @asynccontextmanager
    async def lifespan(_application: FastAPI) -> AsyncIterator[None]:
        yield
        if owns_container:
            resolved_container.close()

    application = FastAPI(
        title=resolved_settings.app_name,
        version=resolved_settings.app_version,
        lifespan=lifespan,
    )
    application.state.settings = resolved_settings
    application.state.container = resolved_container
    application.include_router(router)

    @application.exception_handler(LookupError)
    async def not_found(_request: Request, error: LookupError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"detail": {"code": "not_found", "message": str(error)}},
        )

    @application.exception_handler(ValueError)
    async def invalid_domain_input(_request: Request, error: ValueError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content={"detail": {"code": "invalid_input", "message": str(error)}},
        )

    @application.get("/health", response_model=HealthResponse, tags=["system"])
    def health() -> HealthResponse:
        resolved_container.check_database()
        return HealthResponse(
            service=resolved_settings.app_name,
            environment=resolved_settings.app_env,
            version=resolved_settings.app_version,
        )

    return application


app = create_app()
