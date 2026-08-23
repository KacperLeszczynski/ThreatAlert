import argparse
import re
from pathlib import Path

from sqlalchemy import inspect

from threat_alerting.infrastructure.db import create_database_engine, create_schema
from threat_alerting.settings import Settings

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA_DIRECTORY = PROJECT_ROOT / "data"
DATABASE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a fresh SQLite database with the current application schema."
    )
    parser.add_argument("name", help="Database name, with or without the .db extension")
    parser.add_argument(
        "--directory",
        type=Path,
        default=DEFAULT_DATA_DIRECTORY,
        help="Target directory (default: repository data directory)",
    )
    return parser.parse_args()


def database_filename(name: str) -> str:
    normalized = name.strip()
    if not normalized or not DATABASE_NAME.fullmatch(normalized):
        raise ValueError(
            "database name may contain only letters, numbers, dots, hyphens, and underscores"
        )

    if normalized.lower().endswith(".db"):
        return normalized
    if Path(normalized).suffix:
        raise ValueError("database name must use the .db extension or no extension")
    return f"{normalized}.db"


def create_database(
    name: str, directory: Path = DEFAULT_DATA_DIRECTORY
) -> tuple[Path, tuple[str, ...]]:
    database_path = (directory.resolve() / database_filename(name)).resolve()
    if database_path.exists():
        raise FileExistsError(f"database already exists: {database_path}")

    settings = Settings(
        database_url=f"sqlite+pysqlite:///{database_path.as_posix()}",
        app_env="development",
        _env_file=None,
    )
    engine = create_database_engine(settings)
    try:
        create_schema(engine)
        table_names = tuple(sorted(inspect(engine).get_table_names()))
    finally:
        engine.dispose()

    return database_path, table_names


def main() -> int:
    arguments = parse_args()
    try:
        database_path, table_names = create_database(arguments.name, arguments.directory)
    except (FileExistsError, ValueError) as error:
        print(f"Error: {error}")
        return 1

    database_url = f"sqlite+pysqlite:///{database_path.as_posix()}"
    print(f"Created database: {database_path}")
    print(f"Created tables ({len(table_names)}): {', '.join(table_names)}")
    print(f'DATABASE_URL="{database_url}"')
    print(f'$env:DATABASE_URL = "{database_url}"')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
