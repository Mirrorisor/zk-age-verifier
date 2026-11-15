"""The vendored upstream example proof verified by each backend.

The example request carries a complete proof but a wire shape the service's
parser rejects (``test_upstream_response.py``), so these tests call
pylongfellow directly. The isrg-rust case supplies the assumed empty
device-namespace map (https://github.com/pipe23-org/pylongfellow/issues/29).
"""

import base64
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import cbor2
import pytest
from pylongfellow import Pylongfellow, mdoc

from zk_age_verifier.core.engine.circuits import CircuitSpec

# Calls pylongfellow directly, never the socket: skipped under --transport=live.
pytestmark = pytest.mark.inprocess_only

DATA = Path(__file__).parent.parent / "data"

DOC_TYPE = "org.iso.18013.5.1.mDL"


@dataclass(frozen=True)
class Specimen:
    """The specimen's full verify input set, assembled from ``tests/data/``."""

    spec: CircuitSpec
    circuit: bytes
    proof: bytes
    transcript: bytes
    issuer_public_key: mdoc.PublicKey
    timestamp: datetime
    claims: list[mdoc.RequestedAttribute]


@pytest.fixture(scope="module")
def specimen() -> Specimen:
    """Assemble the verify inputs; proof and transcript come from the wire capture."""
    sidecar = json.loads((DATA / "v6-1attr.json").read_text())
    spec = CircuitSpec(
        system=sidecar["system"],
        circuit_hash=sidecar["circuit_id"],
        num_attributes=sidecar["num_attributes"],
        version=sidecar["version"],
        block_enc_hash=sidecar["block_enc_hash"],
        block_enc_sig=sidecar["block_enc_sig"],
    )

    request = json.loads((DATA / "upstream-verifier-service-request.json").read_text())
    response = cbor2.loads(base64.b64decode(request["ZKDeviceResponseCBOR"]))
    proof: bytes = response["zkDocuments"][0]["proof"]
    transcript = base64.b64decode(request["Transcript"])

    record = json.loads((DATA / "mdl-age-over-18-presentation.json").read_text())
    assert record["doctype"] == DOC_TYPE
    assert transcript == bytes.fromhex(record["transcript_hex"])

    return Specimen(
        spec=spec,
        circuit=(DATA / "v6-1attr.circuit").read_bytes(),
        proof=proof,
        transcript=transcript,
        issuer_public_key=mdoc.PublicKey(
            int(record["issuer_pk_x"], 16), int(record["issuer_pk_y"], 16)
        ),
        timestamp=datetime.fromisoformat(record["timestamp"]),
        claims=[
            mdoc.RequestedAttribute(a["namespace"], a["id"], bytes.fromhex(a["cbor_value_hex"]))
            for a in record["attrs"]
        ],
    )


def test_google_cpp_verifies(specimen: Specimen) -> None:
    verifier = Pylongfellow(backend="google-cpp")
    verifier.load_circuit(specimen.circuit, specimen.spec.version, specimen.spec.num_attributes)
    verifier.verify(
        specimen.issuer_public_key,
        specimen.transcript,
        specimen.claims,
        specimen.timestamp,
        specimen.proof,
        DOC_TYPE,
    )


def test_isrg_rust_verifies_given_empty_device_namespaces(specimen: Specimen) -> None:
    verifier = Pylongfellow(backend="isrg-rust")
    verifier.load_circuit(specimen.circuit, specimen.spec.version, specimen.spec.num_attributes)
    verifier.verify(
        specimen.issuer_public_key,
        specimen.transcript,
        specimen.claims,
        specimen.timestamp,
        specimen.proof,
        DOC_TYPE,
        device_namespaces=b"\xa0",
    )
