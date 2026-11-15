import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from zk_age_verifier.core.engine.circuits import CircuitSpec, HeldCircuit

SECRET = int.from_bytes(bytes(range(1, 33)), "big")


@pytest.fixture
def spec(held: HeldCircuit) -> CircuitSpec:
    return held.spec


@pytest.fixture
def recipient_key() -> ec.EllipticCurvePublicKey:
    return ec.derive_private_key(SECRET, ec.SECP256R1()).public_key()
