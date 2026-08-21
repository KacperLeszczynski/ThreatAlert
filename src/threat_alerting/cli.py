import argparse
import json
from collections.abc import Callable, Sequence
from pathlib import Path

from threat_alerting.bootstrap import ApplicationContainer, build_container
from threat_alerting.domain import ClientProfileCreate
from threat_alerting.evaluation import EvaluationRunner, load_evaluation_suite

EvaluationRunnerFactory = Callable[[Path | None], EvaluationRunner]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="threat-alerting")
    subcommands = parser.add_subparsers(dest="command", required=True)

    ingest = subcommands.add_parser("ingest", help="Run the ingestion pipeline")
    ingest.add_argument(
        "--fixture",
        choices=("mixed-news",),
        metavar="NAME",
        help="Use the bounded offline demo feed",
    )

    seed = subcommands.add_parser("seed-demo-profile", help="Create a demo profile")
    seed.add_argument("--name", default="Demo Security Team")
    seed.add_argument("--threshold", type=float, default=0.70)

    evaluate = subcommands.add_parser(
        "eval",
        help="Run the transparent offline regression suite",
    )
    evaluate.add_argument(
        "--cases",
        type=Path,
        metavar="PATH",
        help="Load an alternate regression-suite YAML file",
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    container_factory: Callable[[], ApplicationContainer] = build_container,
    evaluation_runner_factory: EvaluationRunnerFactory | None = None,
) -> int:
    arguments = build_parser().parse_args(argv)
    if arguments.command == "eval":
        factory = evaluation_runner_factory or _build_evaluation_runner
        report = factory(arguments.cases).run()
        print(report.render())
        return 0 if report.succeeded else 1

    container = container_factory()
    try:
        if arguments.command == "ingest":
            result = container.pipeline.run(fixture=arguments.fixture)
        else:
            result = container.profiles.create(
                ClientProfileCreate(
                    name=arguments.name,
                    minimum_score=arguments.threshold,
                )
            )
        print(json.dumps(result.model_dump(mode="json"), indent=2))
        return 0
    finally:
        container.close()


def _build_evaluation_runner(cases_path: Path | None) -> EvaluationRunner:
    suite = load_evaluation_suite(cases_path) if cases_path else load_evaluation_suite()
    return EvaluationRunner(suite)


if __name__ == "__main__":
    raise SystemExit(main())
