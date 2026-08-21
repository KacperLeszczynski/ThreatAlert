from pathlib import Path
from typing import Any

import yaml
from pydantic import TypeAdapter

from threat_alerting.domain.models import SourceDefinition

SOURCE_LIST_ADAPTER = TypeAdapter(list[SourceDefinition])


def load_source_definitions(
    path: str | Path,
    *,
    enabled_only: bool = True,
) -> tuple[SourceDefinition, ...]:
    with Path(path).open(encoding="utf-8") as config_file:
        document: Any = yaml.safe_load(config_file)

    if not isinstance(document, dict) or not isinstance(document.get("sources"), list):
        raise ValueError("source configuration must contain a sources list")

    definitions = SOURCE_LIST_ADAPTER.validate_python(document["sources"])
    if enabled_only:
        definitions = [definition for definition in definitions if definition.enabled]
    return tuple(definitions)
