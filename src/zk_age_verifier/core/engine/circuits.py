"""Circuit identity and the vendored circuit artifact loaded at startup."""

import hashlib
import json
from dataclasses import dataclass
from importlib.resources import files

from pylongfellow import Pylongfellow

# The pinned circuit: the AV profile's proof system, circuit version, and
# attribute count.
SYSTEM = "longfellow-libzk-v1"
CIRCUIT_VERSION = 7
NUM_ATTRIBUTES = 1

_ARTIFACT = "v7-1attr"


@dataclass(frozen=True)
class CircuitSpec:
    """The six values that identify a circuit to a wallet.

    Attributes:
        system: The proof system's name and version.
        circuit_hash: The circuit's identifying hash, in hex.
        num_attributes: The number of attributes the circuit proves over.
        version: The circuit version.
        block_enc_hash: The proof system's ``block_enc_hash`` parameter.
        block_enc_sig: The proof system's ``block_enc_sig`` parameter.
    """

    system: str
    circuit_hash: str
    num_attributes: int
    version: int
    block_enc_hash: int
    block_enc_sig: int


def zk_system_id(spec: CircuitSpec) -> str:
    """Render the in-band circuit-identity string.

    Six underscore-joined tokens: system, version, num_attributes,
    block_enc_hash, block_enc_sig, circuit_hash.

    Args:
        spec: The circuit's spec.

    Returns:
        The ``zkSystemId`` string the wallet matches against.
    """
    return (
        f"{spec.system}_{spec.version}_{spec.num_attributes}_"
        f"{spec.block_enc_hash}_{spec.block_enc_sig}_{spec.circuit_hash}"
    )


@dataclass(frozen=True)
class HeldCircuit:
    """A resolved circuit, its identity, and the Pylongfellow instance holding it.

    Attributes:
        spec: The circuit's spec.
        longfellow: The Pylongfellow instance, bound once for the process, with
            the circuit loaded.
        zk_system_id: The in-band identity string for this circuit.
    """

    spec: CircuitSpec
    longfellow: Pylongfellow
    zk_system_id: str


def load_held_circuit(*, backend: str) -> HeldCircuit:
    """Load the vendored circuit artifact, verify its integrity, and bind an instance.

    The circuit blob and its sidecar ship as package data. The blob is checked
    against the sidecar's ``byte_sha256`` and the spec it describes is checked
    against the pinned system, version, and attribute count. The bound backend
    loads the blob as a circuit of that version and attribute count.

    Args:
        backend: pylongfellow backend registry name. Constructing the instance
            rejects an unknown name and probes availability, so an unusable
            backend fails here, at startup.

    Returns:
        The held circuit.

    Raises:
        ValueError: ``backend`` is not a registered backend name.
        pylongfellow.backends.BackendUnavailableError: The named backend is not
            built into the installed pylongfellow.
        RuntimeError: The blob does not match the sidecar digest, or the sidecar
            spec does not match the pin.
    """
    longfellow = Pylongfellow(backend=backend)
    artifacts = files("zk_age_verifier").joinpath("circuits")
    blob = artifacts.joinpath(f"{_ARTIFACT}.circuit").read_bytes()
    sidecar = json.loads(artifacts.joinpath(f"{_ARTIFACT}.json").read_text())

    digest = hashlib.sha256(blob).hexdigest()
    if digest != sidecar["byte_sha256"]:
        raise RuntimeError(
            f"circuit blob hashes to {digest}, sidecar says {sidecar['byte_sha256']}"
        )

    spec = CircuitSpec(
        system=sidecar["system"],
        circuit_hash=sidecar["circuit_id"],
        num_attributes=sidecar["num_attributes"],
        version=sidecar["version"],
        block_enc_hash=sidecar["block_enc_hash"],
        block_enc_sig=sidecar["block_enc_sig"],
    )
    if (spec.system, spec.version, spec.num_attributes) != (
        SYSTEM,
        CIRCUIT_VERSION,
        NUM_ATTRIBUTES,
    ):
        raise RuntimeError(
            f"vendored circuit is {spec.system} v{spec.version} "
            f"{spec.num_attributes}attr, pinned to {SYSTEM} v{CIRCUIT_VERSION} "
            f"{NUM_ATTRIBUTES}attr"
        )

    longfellow.load_circuit(blob, spec.version, spec.num_attributes)
    return HeldCircuit(spec=spec, longfellow=longfellow, zk_system_id=zk_system_id(spec))
