from datetime import UTC, datetime, tzinfo

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from zk_age_verifier.core import trustlist
from zk_age_verifier.core.engine.circuits import CircuitSpec, HeldCircuit

SECRET = int.from_bytes(bytes(range(1, 33)), "big")


@pytest.fixture
def spec(held: HeldCircuit) -> CircuitSpec:
    return held.spec


@pytest.fixture
def recipient_key() -> ec.EllipticCurvePublicKey:
    return ec.derive_private_key(SECRET, ec.SECP256R1()).public_key()


class _CaptureDayClock:
    """Stand-in for ``trustlist.datetime``: ``now`` is the day the real lists were captured."""

    # The real lists in tests/data were captured on 2026-11-15. Tests that load them run on
    # that day, so they keep passing after the lists' own NextUpdate (production 2027-04-28,
    # acceptance 2027-04-07), when the loader rightly refuses them.
    instant = datetime(2026, 11, 15, 12, tzinfo=UTC)

    @classmethod
    def now(cls, tz: tzinfo) -> datetime:
        return cls.instant.astimezone(tz)

    @staticmethod
    def fromisoformat(text: str) -> datetime:
        return datetime.fromisoformat(text)


@pytest.fixture
def capture_day(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set the trust-list clock to the day the real lists in tests/data were captured."""
    monkeypatch.setattr(trustlist, "datetime", _CaptureDayClock)
