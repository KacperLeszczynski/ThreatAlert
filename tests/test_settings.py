from threat_alerting.settings import Settings


def test_settings_have_safe_defaults_without_secrets() -> None:
    settings = Settings(_env_file=None)

    assert settings.app_env == "development"
    assert settings.log_level == "INFO"
    assert settings.database_url == "sqlite+pysqlite:///./data/threat_alerting.db"
    assert settings.sources_config_path == "config/sources.yaml"
    assert settings.rss_timeout_seconds == 10.0
    assert settings.rss_max_attempts == 3
    assert settings.max_articles_per_source == 10
    assert settings.max_cves_for_immediate_assessment == 10
    assert settings.article_max_characters == 12_000
    assert settings.llm_provider == "fake"
    assert settings.llm_api_key is None
    assert settings.llm_max_attempts == 3
    assert settings.llm_schema_max_attempts == 2
    assert settings.llm_max_output_tokens == 2_000
    assert settings.llm_timeout_seconds == 30.0
    assert settings.assessment_version == "v1"
    assert settings.summary_confidence_multiplier == 0.75
    assert settings.disagreement_review_threshold == 0.40
    assert settings.borderline_margin == 0.05
    assert settings.invalid_evidence_high_score_threshold == 0.70
    assert "api_key" not in type(settings).model_fields


def test_settings_read_environment_variables(monkeypatch) -> None:
    monkeypatch.setenv("APP_NAME", "Environment Alerting")
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("RSS_MAX_ATTEMPTS", "2")
    monkeypatch.setenv("MAX_ARTICLES_PER_SOURCE", "5")
    monkeypatch.setenv("MAX_CVES_FOR_IMMEDIATE_ASSESSMENT", "7")
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("LLM_MODEL", "configured-model")
    monkeypatch.setenv("LLM_API_KEY", "test-secret")

    settings = Settings(_env_file=None)

    assert settings.app_name == "Environment Alerting"
    assert settings.app_env == "test"
    assert settings.log_level == "DEBUG"
    assert settings.database_url == "sqlite+pysqlite:///:memory:"
    assert settings.rss_max_attempts == 2
    assert settings.max_articles_per_source == 5
    assert settings.max_cves_for_immediate_assessment == 7
    assert settings.llm_provider == "openai"
    assert settings.llm_model == "configured-model"
    assert settings.llm_api_key is not None
    assert settings.llm_api_key.get_secret_value() == "test-secret"
