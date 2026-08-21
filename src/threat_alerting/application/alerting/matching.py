import re
import unicodedata

from threat_alerting.domain import ClientProfile, ProfileMatchResult, ThreatEvent

_SEPARATORS = re.compile(r"[^\w]+", re.UNICODE)
_UNDERSCORES = re.compile(r"_+")


def normalize_filter(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).strip().casefold()
    normalized = _SEPARATORS.sub("_", normalized)
    return _UNDERSCORES.sub("_", normalized).strip("_")


def normalize_filters(values: tuple[str, ...]) -> tuple[str, ...]:
    normalized = {normalize_filter(value) for value in values}
    if "" in normalized:
        raise ValueError("profile filters must contain alphanumeric characters")
    return tuple(sorted(normalized))


class ProfileMatcher:
    def match(self, profile: ClientProfile, event: ThreatEvent) -> ProfileMatchResult:
        profile_filters = {
            "vendor": normalize_filters(profile.vendors),
            "product": normalize_filters(profile.products),
            "category": normalize_filters(profile.categories),
        }
        if not any(profile_filters.values()):
            return ProfileMatchResult(
                matched=True,
                matched_by=("all:empty_filters",),
                reason_codes=("profile_matched",),
            )

        event_values = {
            "vendor": set(normalize_filters(event.vendors)),
            "product": set(normalize_filters(event.products)),
            "category": set(normalize_filters(event.categories)),
        }
        matched_by = tuple(
            f"{filter_name}:{value}"
            for filter_name, values in profile_filters.items()
            for value in values
            if value in event_values[filter_name]
        )
        if matched_by:
            return ProfileMatchResult(
                matched=True,
                matched_by=matched_by,
                reason_codes=("profile_matched",),
            )
        return ProfileMatchResult(
            matched=False,
            reason_codes=("profile_filter_mismatch",),
        )
