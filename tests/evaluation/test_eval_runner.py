from pathlib import Path

import pytest
import yaml

from threat_alerting.cli import main as cli_main
from threat_alerting.evaluation import (
    DEFAULT_CASES_PATH,
    EvaluationRunner,
    load_evaluation_suite,
)
from threat_alerting.evaluation.metrics import calculate_classification_metrics

REQUIRED_CASE_IDS = {
    "actively_exploited_critical_vulnerability",
    "old_vulnerability_without_exploitation",
    "material_data_breach",
    "marketing_product_announcement",
    "sensational_unsupported_claim",
    "prompt_injection",
    "score_equal_to_threshold",
    "llm_failure",
    "duplicate_article",
    "same_cve_two_sources",
}
REQUIRED_DEMONSTRATIONS = {
    "obvious_alert",
    "correct_rejection",
    "evaluator_disagreement",
    "idempotent_rerun",
    "llm_failure",
    "regression_report",
}


@pytest.fixture(scope="module")
def evaluation_report():
    return EvaluationRunner(load_evaluation_suite()).run()


def test_default_runner_passes_all_cases_and_is_repeatable(evaluation_report) -> None:
    repeated = EvaluationRunner(load_evaluation_suite()).run()

    assert evaluation_report.succeeded is True
    assert evaluation_report.passed == 10
    assert evaluation_report.failed == 0
    assert repeated.render() == evaluation_report.render()


def test_every_promised_case_and_interview_scenario_is_represented(
    evaluation_report,
) -> None:
    suite = load_evaluation_suite()
    case_ids = {case.id for case in suite.cases}
    demonstrations = {
        *suite.demonstrates,
        *(item for case in suite.cases for item in case.demonstrates),
    }

    assert case_ids == REQUIRED_CASE_IDS
    assert demonstrations == REQUIRED_DEMONSTRATIONS
    assert len(evaluation_report.cases) == 10


def test_adversarial_and_reliability_cases_validate_observed_state(
    evaluation_report,
) -> None:
    by_id = {case.case_id: case for case in evaluation_report.cases}

    injection = by_id["prompt_injection"]
    assert injection.passed is True
    assert injection.actual_decision == "no_alert"

    duplicate = by_id["duplicate_article"]
    assert duplicate.passed is True
    assert duplicate.duplicates_skipped == 1
    assert (duplicate.article_count, duplicate.event_count) == (1, 1)
    assert (duplicate.assessment_count, duplicate.alert_count) == (1, 1)

    corroborated = by_id["same_cve_two_sources"]
    assert corroborated.passed is True
    assert corroborated.article_count == 2
    assert corroborated.event_count == 1
    assert corroborated.source_count == 2

    failure = by_id["llm_failure"]
    assert failure.actual_decision == "incomplete"
    assert failure.assessment_status == "incomplete"
    assert failure.alert_count == 0
    assert dict(failure.provider_calls)["urgency_expert"] == 2


def test_metrics_use_none_for_undefined_precision_and_recall() -> None:
    metrics = calculate_classification_metrics(())

    assert metrics.precision is None
    assert metrics.recall is None
    assert metrics.unclassified == 0


def test_altered_expectation_returns_nonzero_cli_exit_code(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload = yaml.safe_load(DEFAULT_CASES_PATH.read_text(encoding="utf-8"))
    payload["cases"] = payload["cases"][:1]
    payload["cases"][0]["expected"]["decision"] = "no_alert"
    altered_path = tmp_path / "altered-cases.yaml"
    altered_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    exit_code = cli_main(["eval", "--cases", str(altered_path)])
    output = capsys.readouterr().out

    assert exit_code == 1
    assert "[FAIL] actively_exploited_critical_vulnerability" in output
    assert "failed=1" in output


def test_eval_does_not_build_runtime_container_or_modify_normal_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    developer_database = tmp_path / "developer.db"
    developer_database.write_bytes(b"developer database sentinel")
    original = developer_database.read_bytes()
    monkeypatch.setenv(
        "DATABASE_URL",
        f"sqlite+pysqlite:///{developer_database.as_posix()}",
    )
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("LLM_API_KEY", "must-not-be-used")

    payload = yaml.safe_load(DEFAULT_CASES_PATH.read_text(encoding="utf-8"))
    payload["cases"] = payload["cases"][:1]
    cases_path = tmp_path / "one-case.yaml"
    cases_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    def fail_if_container_is_built():
        raise AssertionError("eval must not build the normal runtime container")

    exit_code = cli_main(
        ["eval", "--cases", str(cases_path)],
        container_factory=fail_if_container_is_built,
    )
    capsys.readouterr()

    assert exit_code == 0
    assert developer_database.read_bytes() == original
