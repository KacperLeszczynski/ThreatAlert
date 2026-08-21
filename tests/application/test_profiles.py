from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import Engine

from threat_alerting.application import ClientProfileService, ProfileMatcher
from threat_alerting.domain import (
    ClientProfile,
    ClientProfileCreate,
    ClientProfileUpdate,
    ThreatEvent,
)
from threat_alerting.infrastructure.db import (
    SessionFactory,
    SqlAlchemyUnitOfWork,
    create_database_engine,
    create_schema,
    create_session_factory,
)
from threat_alerting.settings import Settings

NOW = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)


@pytest.fixture
def database(tmp_path: Path) -> Iterator[tuple[Engine, SessionFactory]]:
    database_path = (tmp_path / "profiles.db").as_posix()
    settings = Settings(
        database_url=f"sqlite+pysqlite:///{database_path}",
        app_env="test",
        _env_file=None,
    )
    engine = create_database_engine(settings)
    create_schema(engine)
    yield engine, create_session_factory(engine)
    engine.dispose()


def test_empty_profile_filters_match_all_events() -> None:
    result = ProfileMatcher().match(
        ClientProfile(name="All threats", minimum_score=0.7),
        ThreatEvent(event_key="cve:CVE-2026-12345"),
    )

    assert result.matched is True
    assert result.matched_by == ("all:empty_filters",)


@pytest.mark.parametrize(
    ("profile_fields", "event_fields", "expected_reason"),
    [
        ({"vendors": (" ACME, Inc. ",)}, {"vendors": ("acme-inc",)}, "vendor:acme_inc"),
        (
            {"products": ("Secure Gateway",)},
            {"products": ("secure_gateway",)},
            "product:secure_gateway",
        ),
        (
            {"categories": ("Active Exploitation",)},
            {"categories": ("active-exploitation",)},
            "category:active_exploitation",
        ),
    ],
)
def test_vendor_product_and_category_matching_is_normalized(
    profile_fields: dict,
    event_fields: dict,
    expected_reason: str,
) -> None:
    profile = ClientProfile(name="Payments", minimum_score=0.7, **profile_fields)
    event = ThreatEvent(event_key="cve:CVE-2026-12345", **event_fields)

    result = ProfileMatcher().match(profile, event)

    assert result.matched is True
    assert expected_reason in result.matched_by


def test_one_intersection_is_enough_across_multiple_non_empty_filters() -> None:
    profile = ClientProfile(
        name="Payments",
        minimum_score=0.7,
        vendors=("Different Vendor",),
        categories=("RCE",),
    )
    event = ThreatEvent(
        event_key="cve:CVE-2026-12345",
        vendors=("Acme",),
        categories=("rce",),
    )

    result = ProfileMatcher().match(profile, event)

    assert result.matched is True
    assert result.matched_by == ("category:rce",)


def test_profile_service_creates_reads_updates_and_lists_normalized_profiles(
    database: tuple[Engine, SessionFactory],
) -> None:
    _, session_factory = database
    service = ClientProfileService(
        lambda: SqlAlchemyUnitOfWork(session_factory),
        clock=lambda: NOW,
    )

    created = service.create(
        ClientProfileCreate(
            name="Payments",
            minimum_score=0.7,
            vendors=(" ACME, Inc. ", "acme-inc"),
            products=("Secure Gateway",),
            categories=("Active Exploitation",),
        )
    )

    assert created.vendors == ("acme_inc",)
    assert created.products == ("secure_gateway",)
    assert created.categories == ("active_exploitation",)
    assert service.get(created.id) == created

    updated = service.update(
        created.id,
        ClientProfileUpdate(
            minimum_score=0.8,
            categories=("Remote Code Execution",),
            enabled=False,
        ),
    )

    assert updated.minimum_score == 0.8
    assert updated.categories == ("remote_code_execution",)
    assert updated.enabled is False
    assert service.list() == (updated,)
    assert service.list(enabled_only=True) == ()


def test_profile_threshold_must_be_within_unit_interval() -> None:
    with pytest.raises(ValidationError):
        ClientProfileCreate(name="Invalid", minimum_score=1.01)
