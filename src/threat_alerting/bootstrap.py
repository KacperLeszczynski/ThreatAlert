from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from pathlib import Path

from sqlalchemy import Engine, text

from threat_alerting.application import (
    AlertDecisionService,
    AlertDeliveryService,
    ArticleNormalizer,
    AssessmentService,
    ClientProfileService,
    DeterministicRiskEvaluator,
    DeterministicScoringConfig,
    ImpactExpert,
    IngestionService,
    PipelineRunService,
    ReadService,
    RiskAssessmentGraph,
    ThreatEventCorrelationService,
    UrgencyExpert,
)
from threat_alerting.domain import ContentMode, SourceDefinition
from threat_alerting.infrastructure.db.session import (
    create_database_engine,
    create_schema,
    create_session_factory,
)
from threat_alerting.infrastructure.db.unit_of_work import SqlAlchemyUnitOfWork
from threat_alerting.infrastructure.delivery import InAppAlertChannel
from threat_alerting.infrastructure.llm import create_llm_provider
from threat_alerting.infrastructure.rss import (
    FixtureFeedTransport,
    HttpxFeedTransport,
    RetryPolicy,
    RSSFeedSource,
    create_configured_rss_sources,
    load_source_definitions,
)
from threat_alerting.observability import configure_application_logging
from threat_alerting.settings import Settings, get_settings

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_URL = "https://fixture.local/stage7-demo.xml"
FIXTURE_PATH = PROJECT_ROOT / "config" / "fixtures" / "stage7_demo.xml"
FIXTURE_NAME = "mixed-news"
FIXTURE_SOURCE = SourceDefinition(
    name="stage7-demo",
    url=FIXTURE_URL,
    content_mode=ContentMode.FULL_RSS,
    trust_score=0.90,
)


@dataclass
class ApplicationContainer:
    settings: Settings
    engine: Engine
    profiles: ClientProfileService
    reads: ReadService
    pipeline: PipelineRunService
    _rss_transport: HttpxFeedTransport

    def check_database(self) -> None:
        with self.engine.connect() as connection:
            connection.execute(text("SELECT 1"))

    def close(self) -> None:
        self._rss_transport.close()
        self.engine.dispose()


def build_container(settings: Settings | None = None) -> ApplicationContainer:
    resolved_settings = _resolve_runtime_paths(settings or get_settings())
    configure_application_logging(resolved_settings.log_level)
    engine = create_database_engine(resolved_settings)
    create_schema(engine)
    session_factory = create_session_factory(engine)
    unit_of_work_factory = partial(SqlAlchemyUnitOfWork, session_factory)

    source_definitions = load_source_definitions(resolved_settings.sources_config_path)
    source_trust_scores = {
        definition.name: definition.trust_score for definition in source_definitions
    }
    source_trust_scores[FIXTURE_SOURCE.name] = FIXTURE_SOURCE.trust_score

    provider = create_llm_provider(resolved_settings)
    evaluator_options = {
        "max_attempts": resolved_settings.llm_max_attempts,
        "schema_max_attempts": resolved_settings.llm_schema_max_attempts,
        "backoff_base_seconds": resolved_settings.llm_backoff_base_seconds,
        "article_max_characters": resolved_settings.article_max_characters,
        "summary_confidence_multiplier": resolved_settings.summary_confidence_multiplier,
    }
    graph = RiskAssessmentGraph(
        (
            DeterministicRiskEvaluator(
                DeterministicScoringConfig(
                    summary_confidence_multiplier=(resolved_settings.summary_confidence_multiplier)
                )
            ),
            ImpactExpert(provider, **evaluator_options),
            UrgencyExpert(provider, **evaluator_options),
        )
    )
    assessment_service = AssessmentService(
        unit_of_work_factory,
        graph,
        assessment_version=resolved_settings.assessment_version,
        source_trust_scores=source_trust_scores,
    )
    profile_service = ClientProfileService(unit_of_work_factory)
    decision_service = AlertDecisionService(
        unit_of_work_factory,
        disagreement_review_threshold=resolved_settings.disagreement_review_threshold,
        borderline_margin=resolved_settings.borderline_margin,
        invalid_evidence_high_score_threshold=(
            resolved_settings.invalid_evidence_high_score_threshold
        ),
    )
    delivery_service = AlertDeliveryService(unit_of_work_factory)
    read_service = ReadService(unit_of_work_factory)
    rss_transport = HttpxFeedTransport()

    ingestion_factory = _build_ingestion_factory(
        resolved_settings,
        unit_of_work_factory,
        rss_transport,
    )
    pipeline_service = PipelineRunService(
        ingestion_factory,
        assessment_service,
        profile_service,
        decision_service,
        delivery_service,
        InAppAlertChannel(),
    )
    return ApplicationContainer(
        settings=resolved_settings,
        engine=engine,
        profiles=profile_service,
        reads=read_service,
        pipeline=pipeline_service,
        _rss_transport=rss_transport,
    )


def _build_ingestion_factory(
    settings: Settings,
    unit_of_work_factory: Callable[[], SqlAlchemyUnitOfWork],
    rss_transport: HttpxFeedTransport,
):
    normalizer = ArticleNormalizer(max_characters=settings.article_max_characters)
    correlator = ThreatEventCorrelationService()

    def create(fixture: str | None, run_id: str) -> IngestionService:
        if fixture is not None:
            if settings.app_env == "production":
                raise ValueError("fixture ingestion is disabled in production")
            if fixture != FIXTURE_NAME:
                raise ValueError(f"unknown ingestion fixture: {fixture}")
            fixture_transport = FixtureFeedTransport({FIXTURE_URL: FIXTURE_PATH.read_bytes()})
            sources = (
                RSSFeedSource(
                    FIXTURE_SOURCE,
                    fixture_transport,
                    retry_policy=_retry_policy(settings),
                    max_entries=settings.max_articles_per_source,
                ),
            )
        else:
            sources = create_configured_rss_sources(settings, rss_transport)
        return IngestionService(
            sources,
            unit_of_work_factory,
            normalizer,
            article_correlator=correlator,
            run_id_factory=lambda: run_id,
        )

    return create


def _retry_policy(settings: Settings) -> RetryPolicy:
    return RetryPolicy(
        max_attempts=settings.rss_max_attempts,
        timeout_seconds=settings.rss_timeout_seconds,
        base_delay_seconds=settings.rss_backoff_base_seconds,
    )


def _resolve_runtime_paths(settings: Settings) -> Settings:
    source_path = Path(settings.sources_config_path)
    if source_path.is_absolute():
        return settings
    return settings.model_copy(update={"sources_config_path": str(PROJECT_ROOT / source_path)})
