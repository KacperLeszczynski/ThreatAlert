from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status

from threat_alerting.api.schemas import DecisionCertificateResponse, IngestionRunRequest
from threat_alerting.bootstrap import ApplicationContainer
from threat_alerting.domain import (
    Alert,
    Assessment,
    ClientProfile,
    ClientProfileCreate,
    ClientProfileUpdate,
    NewsArticle,
    PipelineRunSummary,
)

router = APIRouter(prefix="/api/v1")
Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0)]


def _container(request: Request) -> ApplicationContainer:
    return request.app.state.container


Container = Annotated[ApplicationContainer, Depends(_container)]


@router.post(
    "/profiles",
    response_model=ClientProfile,
    status_code=status.HTTP_201_CREATED,
    tags=["profiles"],
)
def create_profile(command: ClientProfileCreate, container: Container) -> ClientProfile:
    return container.profiles.create(command)


@router.get("/profiles", response_model=list[ClientProfile], tags=["profiles"])
def list_profiles(
    container: Container,
    limit: Limit = 50,
    offset: Offset = 0,
) -> tuple[ClientProfile, ...]:
    return container.profiles.list(limit=limit, offset=offset)


@router.get("/profiles/{profile_id}", response_model=ClientProfile, tags=["profiles"])
def get_profile(profile_id: int, container: Container) -> ClientProfile:
    return container.profiles.get(profile_id)


@router.patch("/profiles/{profile_id}", response_model=ClientProfile, tags=["profiles"])
def update_profile(
    profile_id: int,
    command: ClientProfileUpdate,
    container: Container,
) -> ClientProfile:
    return container.profiles.update(profile_id, command)


@router.post("/runs/ingestion", response_model=PipelineRunSummary, tags=["runs"])
def run_ingestion(
    command: IngestionRunRequest,
    container: Container,
) -> PipelineRunSummary:
    return container.pipeline.run(fixture=command.fixture)


@router.get("/articles", response_model=list[NewsArticle], tags=["read models"])
def list_articles(
    container: Container,
    limit: Limit = 50,
    offset: Offset = 0,
) -> tuple[NewsArticle, ...]:
    return container.reads.list_articles(limit=limit, offset=offset)


@router.get("/assessments", response_model=list[Assessment], tags=["read models"])
def list_assessments(
    container: Container,
    limit: Limit = 50,
    offset: Offset = 0,
) -> tuple[Assessment, ...]:
    return container.reads.list_assessments(limit=limit, offset=offset)


@router.get("/alerts", response_model=list[Alert], tags=["alerts"])
def list_alerts(
    container: Container,
    limit: Limit = 50,
    offset: Offset = 0,
) -> tuple[Alert, ...]:
    return container.reads.list_alerts(limit=limit, offset=offset)


@router.get(
    "/profiles/{profile_id}/alerts",
    response_model=list[Alert],
    tags=["alerts"],
)
def list_profile_alerts(
    profile_id: int,
    container: Container,
    limit: Limit = 50,
    offset: Offset = 0,
) -> tuple[Alert, ...]:
    return container.reads.list_alerts(
        profile_id=profile_id,
        limit=limit,
        offset=offset,
    )


@router.get("/alerts/{alert_id}", response_model=Alert, tags=["alerts"])
def get_alert(alert_id: int, container: Container) -> Alert:
    return container.reads.get_alert(alert_id)


@router.get(
    "/alerts/{alert_id}/decision",
    response_model=DecisionCertificateResponse,
    tags=["alerts"],
)
def get_alert_decision(alert_id: int, container: Container) -> dict:
    return container.reads.get_decision_certificate(alert_id)
