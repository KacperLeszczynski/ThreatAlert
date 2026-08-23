from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = Field(default="Threat Alerting System", min_length=1)
    app_version: str = "0.1.0"
    app_env: Literal["development", "test", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    database_url: str = Field(
        default="sqlite+pysqlite:///./data/threat_alerting.db",
        min_length=1,
    )
    sources_config_path: str = Field(default="config/sources.yaml", min_length=1)
    rss_timeout_seconds: float = Field(default=10.0, gt=0.0, le=60.0)
    rss_max_attempts: int = Field(default=3, ge=1, le=5)
    rss_backoff_base_seconds: float = Field(default=0.5, gt=0.0, le=10.0)
    max_articles_per_source: int = Field(default=10, ge=1, le=100)
    article_max_characters: int = Field(default=12_000, ge=1_000, le=100_000)
    llm_provider: Literal["fake", "openai"] = "fake"
    llm_model: str = Field(default="gpt-5-mini", min_length=1)
    llm_api_key: SecretStr | None = None
    llm_max_attempts: int = Field(default=3, ge=1, le=5)
    llm_schema_max_attempts: int = Field(default=2, ge=1, le=3)
    llm_backoff_base_seconds: float = Field(default=0.5, ge=0.0, le=10.0)
    llm_max_output_tokens: int = Field(default=2_000, ge=500, le=10_000)
    llm_timeout_seconds: float = Field(default=30.0, gt=0.0, le=120.0)
    assessment_version: str = Field(default="v1", min_length=1, max_length=100)
    summary_confidence_multiplier: float = Field(default=0.75, ge=0.0, le=1.0)
    disagreement_review_threshold: float = Field(default=0.40, ge=0.0, le=1.0)
    borderline_margin: float = Field(default=0.05, ge=0.0, le=1.0)
    invalid_evidence_high_score_threshold: float = Field(default=0.70, ge=0.0, le=1.0)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
