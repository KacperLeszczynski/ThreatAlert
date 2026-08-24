import asyncio
import json
from collections.abc import Iterator
from typing import Any
from uuid import UUID

import pytest
from httpx import ASGITransport, AsyncClient, Response

from threat_alerting.bootstrap import ApplicationContainer, build_container
from threat_alerting.cli import main as cli_main
from threat_alerting.main import create_app
from threat_alerting.settings import Settings


class ApiClient:
    def __init__(self, application) -> None:
        self._application = application

    def get(self, path: str) -> Response:
        return self._request("GET", path)

    def post(self, path: str, *, json: dict[str, Any]) -> Response:
        return self._request("POST", path, json=json)

    def patch(self, path: str, *, json: dict[str, Any]) -> Response:
        return self._request("PATCH", path, json=json)

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
    ) -> Response:
        async def execute() -> Response:
            transport = ASGITransport(app=self._application)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                return await client.request(method, path, json=json)

        return asyncio.run(execute())


@pytest.fixture
def container(tmp_path) -> Iterator[ApplicationContainer]:
    database_path = tmp_path / "demo.db"
    settings = Settings(
        _env_file=None,
        app_env="test",
        database_url=f"sqlite+pysqlite:///{database_path.as_posix()}",
        llm_provider="fake",
        llm_api_key=None,
    )
    application_container = build_container(settings)
    yield application_container
    application_container.close()


@pytest.fixture
def client(container: ApplicationContainer) -> ApiClient:
    return ApiClient(create_app(container=container))


def test_profile_api_validates_normalizes_and_persists(client: ApiClient) -> None:
    invalid = client.post(
        "/api/v1/profiles",
        json={"name": "Invalid", "minimum_score": 1.01},
    )
    assert invalid.status_code == 422

    created = client.post(
        "/api/v1/profiles",
        json={
            "name": "Platform Team",
            "minimum_score": 0.65,
            "vendors": ["  ACME  ", "acme"],
            "products": ["Edge Gateway"],
        },
    )
    assert created.status_code == 201
    profile = created.json()
    assert profile["vendors"] == ["acme"]
    assert profile["products"] == ["edge_gateway"]

    updated = client.patch(
        f"/api/v1/profiles/{profile['id']}",
        json={"minimum_score": 0.75, "categories": [" RCE "]},
    )
    assert updated.status_code == 200
    assert updated.json()["minimum_score"] == 0.75
    assert updated.json()["categories"] == ["rce"]

    fetched = client.get(f"/api/v1/profiles/{profile['id']}")
    listed = client.get("/api/v1/profiles")
    assert fetched.json() == updated.json()
    assert listed.json() == [updated.json()]


def test_fixture_ingestion_runs_end_to_end_and_is_idempotent(client: ApiClient) -> None:
    broad_profile = client.post(
        "/api/v1/profiles",
        json={"name": "Broad profile", "minimum_score": 0.70},
    ).json()
    strict_profile = client.post(
        "/api/v1/profiles",
        json={"name": "Strict profile", "minimum_score": 0.90},
    ).json()

    response = client.post(
        "/api/v1/runs/ingestion",
        json={"fixture": "mixed-news"},
    )
    assert response.status_code == 200
    summary = response.json()
    UUID(summary["run_id"])
    assert summary == {
        "run_id": summary["run_id"],
        "sources_attempted": 1,
        "sources_succeeded": 1,
        "sources_failed": 0,
        "articles_seen": 2,
        "articles_new": 2,
        "duplicates_skipped": 0,
        "malformed_entries": 0,
        "assessments_complete": 2,
        "assessments_incomplete": 0,
        "no_alert_decisions": 3,
        "alerts_created": 1,
        "alerts_delivered": 1,
        "alerts_failed": 0,
        "source_failures": [],
    }

    articles = client.get("/api/v1/articles").json()
    assessments = client.get("/api/v1/assessments").json()
    alerts = client.get("/api/v1/alerts").json()
    assert len(articles) == 2
    assert len(assessments) == 2
    assert len(alerts) == 1
    assert alerts[0]["status"] == "sent"
    assert client.get(f"/api/v1/profiles/{broad_profile['id']}/alerts").json() == alerts
    assert client.get(f"/api/v1/profiles/{strict_profile['id']}/alerts").json() == []

    certificate_response = client.get(f"/api/v1/alerts/{alerts[0]['id']}/decision")
    assert certificate_response.status_code == 200
    certificate = certificate_response.json()
    assert certificate["alert_id"] == alerts[0]["id"]
    assert certificate["decision"]["outcome"] == "alert"
    assert certificate["assessment"]["scores"].keys() == {
        "deterministic",
        "impact_expert",
        "urgency_expert",
    }

    repeated = client.post(
        "/api/v1/runs/ingestion",
        json={"fixture": "mixed-news"},
    ).json()
    assert repeated["articles_new"] == 0
    assert repeated["duplicates_skipped"] == 2
    assert repeated["assessments_complete"] == 0
    assert repeated["alerts_created"] == 0
    assert len(client.get("/api/v1/alerts").json()) == 1


def test_read_pagination_is_bounded_and_missing_resources_are_safe(
    client: ApiClient,
) -> None:
    for index in range(3):
        response = client.post(
            "/api/v1/profiles",
            json={"name": f"Profile {index}", "minimum_score": 0.5},
        )
        assert response.status_code == 201

    assert len(client.get("/api/v1/profiles?limit=1&offset=1").json()) == 1
    assert client.get("/api/v1/profiles?limit=101").status_code == 422
    assert client.get("/api/v1/profiles?limit=0").status_code == 422

    missing = client.get("/api/v1/alerts/99999")
    assert missing.status_code == 404
    assert missing.json() == {
        "detail": {
            "code": "not_found",
            "message": "alert 99999 does not exist",
        }
    }
    assert client.get("/api/v1/profiles/99999/alerts").status_code == 404

    invalid_fixture = client.post(
        "/api/v1/runs/ingestion",
        json={"fixture": "not-configured"},
    )
    assert invalid_fixture.status_code == 422
    assert invalid_fixture.json()["detail"]["code"] == "invalid_input"


def test_cli_and_api_use_the_same_pipeline_workflow(
    client: ApiClient,
    container: ApplicationContainer,
    capsys: pytest.CaptureFixture[str],
) -> None:
    client.post(
        "/api/v1/profiles",
        json={"name": "Shared workflow", "minimum_score": 0.70},
    )
    api_summary = client.post(
        "/api/v1/runs/ingestion",
        json={"fixture": "mixed-news"},
    ).json()
    assert api_summary["articles_new"] == 2

    exit_code = cli_main(
        ["ingest", "--fixture", "mixed-news"],
        container_factory=lambda: container,
    )
    cli_summary = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert cli_summary["articles_new"] == 0
    assert cli_summary["duplicates_skipped"] == 2
    assert cli_summary["alerts_created"] == 0


def test_cli_seeds_demo_profile(
    container: ApplicationContainer,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = cli_main(
        ["seed-demo-profile", "--name", "CLI profile", "--threshold", "0.72"],
        container_factory=lambda: container,
    )
    profile = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert profile["name"] == "CLI profile"
    assert profile["minimum_score"] == 0.72
    assert profile["id"] is not None
