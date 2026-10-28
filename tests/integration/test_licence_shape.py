"""A licence-shaped credential verifies when the wallet discloses only what was asked.

A standard ISO driving licence carries many elements and a list-of-maps element
(``driving_privileges``). The prover aborts its whole process on any list or map
element value it is handed, so the presenter, like a wallet, passes it only the
requested elements. This test builds such a licence in memory under throwaway keys.
"""

import hashlib
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import cbor2
import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from pylongfellow.mdoc import testing

from tests.conftest import ORIGIN, render_config
from tests.integration import presenter
from zk_age_verifier.app import create_app
from zk_age_verifier.config import load_config

# Needs a verifier trusting this test's own CA, which the live server does not.
pytestmark = pytest.mark.inprocess_only

DOC_TYPE = "org.iso.18013.5.1.mDL"
NAMESPACE = "org.iso.18013.5.1"
VALID_FROM = datetime(2026, 7, 1, tzinfo=UTC)
VALID_UNTIL = datetime(2036, 7, 1, tzinfo=UTC)
ENTRY = "licence-shaped"

_PLAIN_ELEMENTS: dict[str, Any] = {
    "age_over_18": True,
    "family_name": "Mustermann",
    "given_name": "Erika",
    "birth_date": "1986-03-14",
    "issue_date": "2026-01-01",
    "expiry_date": "2036-01-01",
    "issuing_country": "AU",
    "issuing_authority": "Test Authority",
    "document_number": "A1234567",
    "portrait": b"\x00" * 100,
    "un_distinguishing_sign": "AUS",
    "administrative_number": "ADM-0001",
    "sex": 2,
    "height": 170,
    "weight": 65,
    "eye_colour": "brown",
    "hair_colour": "brown",
    "birth_place": "Perth",
    "resident_address": "1 Test St",
    "resident_city": "Perth",
    "resident_state": "WA",
    "resident_postal_code": "6000",
    "resident_country": "AU",
    "nationality": "AU",
    "issuing_jurisdiction": "AU-WA",
    "age_over_16": True,
    "age_over_21": True,
    "age_over_65": False,
}
_DRIVING_PRIVILEGES = [
    {"vehicle_category_code": "C", "issue_date": "2026-01-01", "expiry_date": "2036-01-01"}
]


def _write_entry(root: Path) -> Path:
    """Write the licence entry and its CA under ``root``; return the CA PEM path."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_cn = "licence-shape test CA"
    ca_cert = testing.create_certificate(
        ca_cn, ca_key.public_key(), ca_cn, ca_key, VALID_FROM, VALID_UNTIL, ca=True
    )
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    leaf = testing.create_certificate(
        "licence-shape test issuer",
        issuer_key.public_key(),
        ca_cn,
        ca_key,
        VALID_FROM,
        VALID_UNTIL,
    )
    claims = {NAMESPACE: {**_PLAIN_ELEMENTS, "driving_privileges": _DRIVING_PRIVILEGES}}
    handover = hashlib.sha256(b"licence-shape credential generation").digest()
    transcript = cbor2.dumps([None, None, ["dcapi", handover]])
    created = testing.create_presentation(
        DOC_TYPE,
        claims,
        transcript,
        VALID_FROM,
        VALID_UNTIL,
        issuer_key=issuer_key,
        issuer_certificate=leaf,
    )

    entry = root / ENTRY
    entry.mkdir(parents=True)
    (entry / "credential.cbor").write_bytes(created.mdoc)
    (entry / "leaf.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (entry / "device-key.pem").write_bytes(
        created.device_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    numbers = issuer_key.public_key().public_numbers()
    claim_lines = [
        f'{element} = "{cbor2.dumps(value).hex()}"' for element, value in claims[NAMESPACE].items()
    ]
    manifest = [
        "[credential]",
        f'doctype = "{DOC_TYPE}"',
        "[issuer]",
        f'pk_x = "{numbers.x:064x}"',
        f'pk_y = "{numbers.y:064x}"',
        "[device]",
        'key = "device-key.pem"',
        "[trust]",
        'certificate = "leaf.pem"',
        f'[claims."{NAMESPACE}"]',
        *claim_lines,
    ]
    (entry / "manifest.toml").write_text("\n".join(manifest) + "\n")
    ca_pem = root / "ca.pem"
    ca_pem.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    return ca_pem


@pytest.fixture(scope="module")
def shaped_client(
    tmp_path_factory: pytest.TempPathFactory, verifier_backend: str
) -> Iterator[httpx.Client]:
    """A licence verifier trusting this module's own CA, with the licence entry loadable."""
    root = tmp_path_factory.mktemp("licence-shape")
    ca_pem = _write_entry(root)
    config_file = root / "config.toml"
    config_file.write_text(
        render_config(
            pem=ca_pem, **{"pylongfellow.backend": verifier_backend, "credential": "iso-mdl"}
        )
    )
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(presenter, "CREDENTIALS_DIR", root)
        presenter.load_credential.cache_clear()
        with TestClient(create_app(load_config(config_file))) as test_client:
            yield test_client
        presenter.load_credential.cache_clear()


def test_licence_with_nested_element_verifies(shaped_client: httpx.Client) -> None:
    created = shaped_client.post("/sessions", json={"checks": ["age_over_18"]})
    assert created.status_code == 201
    session = cast(dict[str, Any], created.json())
    data = presenter.present(session["transports"]["dc"], ORIGIN, credential=ENTRY)

    verdict = shaped_client.post(f"/sessions/{session['session_id']}/presentation", json=data)
    assert verdict.status_code == 200
    body = verdict.json()
    assert body["state"] == "verified"
    assert body["result"] == {"age_over_18": True}
