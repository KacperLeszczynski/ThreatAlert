from threat_alerting.settings import Settings


def test_settings_have_safe_defaults_without_secrets() -> None:
    settings = Settings(_env_file=None)

    assert settings.app_env == "development"
    assert settings.log_level == "INFO"
    assert settings.database_url == "sqlite+pysqlite:///./data/threat_alerting.db"
    assert "api_key" not in type(settings).model_fields


def test_settings_read_environment_variables(monkeypatch) -> None:
    monkeypatch.setenv("APP_NAME", "Environment Alerting")
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")

    settings = Settings(_env_file=None)

    assert settings.app_name == "Environment Alerting"
    assert settings.app_env == "test"
    assert settings.log_level == "DEBUG"
    assert settings.database_url == "sqlite+pysqlite:///:memory:"
