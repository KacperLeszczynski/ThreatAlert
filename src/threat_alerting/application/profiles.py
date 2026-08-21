from collections.abc import Callable
from datetime import UTC, datetime

from threat_alerting.application.profile_matching import normalize_filters
from threat_alerting.domain import ClientProfile, ClientProfileCreate, ClientProfileUpdate
from threat_alerting.domain.ports import AlertUnitOfWork


class ClientProfileService:
    def __init__(
        self,
        unit_of_work_factory: Callable[[], AlertUnitOfWork],
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._unit_of_work_factory = unit_of_work_factory
        self._clock = clock

    def create(self, command: ClientProfileCreate) -> ClientProfile:
        now = self._clock()
        profile = ClientProfile(
            name=command.name,
            minimum_score=command.minimum_score,
            vendors=normalize_filters(command.vendors),
            products=normalize_filters(command.products),
            categories=normalize_filters(command.categories),
            enabled=command.enabled,
            created_at=now,
            updated_at=now,
        )
        with self._unit_of_work_factory() as unit_of_work:
            stored = unit_of_work.client_profiles.add(profile)
            unit_of_work.commit()
        return stored

    def get(self, profile_id: int) -> ClientProfile:
        with self._unit_of_work_factory() as unit_of_work:
            profile = unit_of_work.client_profiles.get(profile_id)
        if profile is None:
            raise LookupError(f"client profile {profile_id} does not exist")
        return profile

    def update(self, profile_id: int, command: ClientProfileUpdate) -> ClientProfile:
        with self._unit_of_work_factory() as unit_of_work:
            profile = unit_of_work.client_profiles.get(profile_id)
            if profile is None:
                raise LookupError(f"client profile {profile_id} does not exist")

            changes = {"updated_at": self._clock()}
            if command.name is not None:
                changes["name"] = command.name
            if command.minimum_score is not None:
                changes["minimum_score"] = command.minimum_score
            if command.vendors is not None:
                changes["vendors"] = normalize_filters(command.vendors)
            if command.products is not None:
                changes["products"] = normalize_filters(command.products)
            if command.categories is not None:
                changes["categories"] = normalize_filters(command.categories)
            if command.enabled is not None:
                changes["enabled"] = command.enabled

            stored = unit_of_work.client_profiles.update(profile.model_copy(update=changes))
            unit_of_work.commit()
        return stored

    def list(self, *, enabled_only: bool = False) -> tuple[ClientProfile, ...]:
        with self._unit_of_work_factory() as unit_of_work:
            profiles = (
                unit_of_work.client_profiles.list_enabled()
                if enabled_only
                else unit_of_work.client_profiles.list_all()
            )
        return tuple(profiles)
