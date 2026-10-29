from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from pylongfellow import mdoc

from tests.conftest import ORIGIN, render_config
from zk_age_verifier.config import Config, load_config
from zk_age_verifier.core.constants import DOC_TYPE, EU_AV, ISO_MDL, PHOTO_ID
from zk_age_verifier.core.encoding import b64url_encode
from zk_age_verifier.core.engine import mdoc_zk
from zk_age_verifier.core.engine.circuits import HeldCircuit
from zk_age_verifier.core.transport.dc import (
    DcSessionState,
    build_session_transcript,
    seal_response,
)
from zk_age_verifier.core.trustlist import AnchorSet
from zk_age_verifier.service.sessions import Session
from zk_age_verifier.service.verify import VerdictFailed, VerdictVerified, verify_response

CLAIMS = ("age_over_18",)
ENCRYPTION_INFO_B64 = b64url_encode(b"encryption-info")


@pytest.fixture
def config(tmp_path: Path) -> Config:
    path = tmp_path / "config.toml"
    path.write_text(render_config())
    return load_config(path)


@pytest.fixture
def session() -> Session:
    now = datetime.now(UTC)
    return Session(
        session_id="pid",
        dc=DcSessionState(
            private_key=ec.generate_private_key(ec.SECP256R1()),
            encryption_info_b64=ENCRYPTION_INFO_B64,
        ),
        expected_origin=ORIGIN,
        claims=CLAIMS,
        created_at=now,
        expires_at=now + timedelta(seconds=300),
    )


def _anchor_cert() -> tuple[x509.Certificate, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DS")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, cert.public_bytes(Encoding.DER)


def _document_data(held: HeldCircuit, chain_der: bytes, **overrides: object) -> bytes:
    data: dict[str, object] = {
        "zkSystemId": held.zk_system_id,
        "docType": DOC_TYPE,
        "timestamp": datetime.now(UTC),
        "issuerSigned": {DOC_TYPE: [{"elementIdentifier": "age_over_18", "elementValue": True}]},
        "deviceSigned": {},
        "msoX5chain": chain_der,
    }
    data.update(overrides)
    return cbor2.dumps(data)


def _device_response(held: HeldCircuit, chain_der: bytes, **overrides: object) -> bytes:
    document = {
        "proof": b"proof-bytes",
        "documentData": cbor2.CBORTag(24, _document_data(held, chain_der, **overrides)),
    }
    return cbor2.dumps({"version": "1.0", "status": 0, "zkDocuments": [document]})


def _body(session: Session, plaintext: bytes, *, origin: str = ORIGIN) -> dict[str, object]:
    transcript = build_session_transcript(session.dc.encryption_info_b64, origin)
    enc, ciphertext = seal_response(plaintext, session.dc.private_key.public_key(), transcript)
    wrapper = cbor2.dumps(["dcapi", {"enc": enc, "cipherText": ciphertext}])
    return {"response": b64url_encode(wrapper)}


async def test_verified_happy_path(
    session: Session, held: HeldCircuit, config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    cert, chain = _anchor_cert()
    monkeypatch.setattr(held.longfellow, "verify", lambda *_a, **_k: None)
    body = _body(session, _device_response(held, chain))
    verdict = await verify_response(session, held, AnchorSet((cert,)), body, config)
    assert isinstance(verdict, VerdictVerified)
    assert verdict.result == {"age_over_18": True}
    assert verdict.verified_at.endswith("Z")


@pytest.fixture
def mdl_config(tmp_path: Path) -> Config:
    path = tmp_path / "mdl-config.toml"
    path.write_text(render_config(credential="iso-mdl"))
    return load_config(path)


def _mdl_response(held: HeldCircuit, chain_der: bytes, **overrides: object) -> bytes:
    fields: dict[str, object] = {
        "docType": ISO_MDL.doc_type,
        "issuerSigned": {
            ISO_MDL.namespace: [{"elementIdentifier": "age_over_18", "elementValue": True}]
        },
    }
    fields.update(overrides)
    return _device_response(held, chain_der, **fields)


async def test_licence_profile_verifies_and_binds_the_proof_to_the_licence(
    session: Session, held: HeldCircuit, mdl_config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    cert, chain = _anchor_cert()
    seen: dict[str, object] = {}

    def _record(*args: object, **_kwargs: object) -> None:
        seen["doc_type"] = args[5]
        seen["requested"] = args[2]

    monkeypatch.setattr(mdoc, "RequestedAttribute", lambda *fields: fields)
    monkeypatch.setattr(held.longfellow, "verify", _record)
    body = _body(session, _mdl_response(held, chain))
    verdict = await verify_response(session, held, AnchorSet((cert,)), body, mdl_config)
    assert isinstance(verdict, VerdictVerified)
    assert seen["doc_type"] == "org.iso.18013.5.1.mDL"
    assert seen["requested"] == [("org.iso.18013.5.1", "age_over_18", cbor2.dumps(True))]


@pytest.fixture
def both_config(tmp_path: Path) -> Config:
    path = tmp_path / "both-config.toml"
    path.write_text(render_config(credential=["eu-av", "iso-mdl"]))
    return load_config(path)


@pytest.mark.parametrize("kind", ["eu-av", "iso-mdl"])
async def test_a_service_accepting_both_verifies_either_and_binds_to_its_doctype(
    session: Session,
    held: HeldCircuit,
    both_config: Config,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    cert, chain = _anchor_cert()
    seen: dict[str, object] = {}

    def _record(*args: object, **_kwargs: object) -> None:
        seen["doc_type"] = args[5]
        seen["requested"] = args[2]

    monkeypatch.setattr(mdoc, "RequestedAttribute", lambda *fields: fields)
    monkeypatch.setattr(held.longfellow, "verify", _record)
    profile = ISO_MDL if kind == "iso-mdl" else EU_AV
    response = _mdl_response(held, chain) if kind == "iso-mdl" else _device_response(held, chain)
    verdict = await verify_response(
        session, held, AnchorSet((cert,)), _body(session, response), both_config
    )
    assert isinstance(verdict, VerdictVerified)
    assert seen["doc_type"] == profile.doc_type
    assert seen["requested"] == [(profile.namespace, "age_over_18", cbor2.dumps(True))]


async def test_a_service_accepting_both_still_refuses_another_doctype(
    session: Session, held: HeldCircuit, both_config: Config
) -> None:
    other = _mdl_response(held, _anchor_cert()[1], docType="org.example.other.1")
    verdict = await verify_response(
        session, held, AnchorSet(()), _body(session, other), both_config
    )
    assert verdict == VerdictFailed(state="failed", reason="claim-mismatch")


async def test_licence_profile_refuses_the_eu_credential(
    session: Session, held: HeldCircuit, mdl_config: Config
) -> None:
    body = _body(session, _device_response(held, _anchor_cert()[1]))
    verdict = await verify_response(session, held, AnchorSet(()), body, mdl_config)
    assert verdict == VerdictFailed(state="failed", reason="claim-mismatch")


async def test_eu_profile_refuses_the_licence(
    session: Session, held: HeldCircuit, config: Config
) -> None:
    body = _body(session, _mdl_response(held, _anchor_cert()[1]))
    verdict = await verify_response(session, held, AnchorSet(()), body, config)
    assert verdict == VerdictFailed(state="failed", reason="claim-mismatch")


async def test_licence_profile_wants_the_claim_in_the_licence_namespace(
    session: Session, held: HeldCircuit, mdl_config: Config
) -> None:
    # Right doctype, but the claim sits under the doctype string: that is the EU
    # layout, not the licence's, so it must not satisfy this profile.
    wrong_place = {ISO_MDL.doc_type: [{"elementIdentifier": "age_over_18", "elementValue": True}]}
    body = _body(session, _mdl_response(held, _anchor_cert()[1], issuerSigned=wrong_place))
    verdict = await verify_response(session, held, AnchorSet(()), body, mdl_config)
    assert verdict == VerdictFailed(state="failed", reason="claim-mismatch")


async def test_absent_device_namespaces_verify_under_assumption(
    session: Session, held: HeldCircuit, config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    cert, chain = _anchor_cert()
    recorded: dict[str, object] = {}

    def _record(*_args: object, **kwargs: object) -> None:
        recorded.update(kwargs)

    monkeypatch.setattr(held.longfellow, "verify", _record)
    body = _body(session, _device_response(held, chain))
    verdict = await verify_response(session, held, AnchorSet((cert,)), body, config)
    assert isinstance(verdict, VerdictVerified)
    assert recorded["device_namespaces"] == b"\xa0"


async def test_wire_device_namespaces_reach_verify_unchanged(
    session: Session, held: HeldCircuit, config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No expressible presentation parses to a non-None value today; the parser
    # is bypassed to pin that the assumption substitutes only for absence.
    wire_value = cbor2.dumps({"a": True})
    cert, chain = _anchor_cert()
    recorded: dict[str, object] = {}

    def _record(*_args: object, **kwargs: object) -> None:
        recorded.update(kwargs)

    monkeypatch.setattr(held.longfellow, "verify", _record)
    real_parse = mdoc_zk.parse_device_response
    monkeypatch.setattr(
        mdoc_zk,
        "parse_device_response",
        lambda plaintext: replace(real_parse(plaintext), device_name_spaces_bytes=wire_value),
    )
    body = _body(session, _device_response(held, chain))
    verdict = await verify_response(session, held, AnchorSet((cert,)), body, config)
    assert isinstance(verdict, VerdictVerified)
    assert recorded["device_namespaces"] == wire_value


async def test_invalid_envelope(session: Session, held: HeldCircuit, config: Config) -> None:
    verdict = await verify_response(session, held, AnchorSet(()), {"response": 5}, config)
    assert verdict == VerdictFailed(state="failed", reason="invalid-envelope")


async def test_decrypt_failed(session: Session, held: HeldCircuit, config: Config) -> None:
    body = _body(session, _device_response(held, _anchor_cert()[1]), origin="https://wrong.example")
    verdict = await verify_response(session, held, AnchorSet(()), body, config)
    assert verdict == VerdictFailed(state="failed", reason="decrypt-failed")


async def test_standard_mdoc_not_accepted(
    session: Session, held: HeldCircuit, config: Config
) -> None:
    body = _body(session, cbor2.dumps({"documents": [{"docType": DOC_TYPE}]}))
    verdict = await verify_response(session, held, AnchorSet(()), body, config)
    assert verdict == VerdictFailed(state="failed", reason="standard-mdoc-not-accepted")


async def test_malformed_device_response(
    session: Session, held: HeldCircuit, config: Config
) -> None:
    body = _body(session, cbor2.dumps({"version": "1.0"}))
    verdict = await verify_response(session, held, AnchorSet(()), body, config)
    assert verdict == VerdictFailed(state="failed", reason="invalid-envelope")


async def test_unsupported_circuit(session: Session, held: HeldCircuit, config: Config) -> None:
    body = _body(session, _device_response(held, _anchor_cert()[1], zkSystemId="other-circuit"))
    verdict = await verify_response(session, held, AnchorSet(()), body, config)
    assert verdict == VerdictFailed(state="failed", reason="unsupported-circuit")


async def test_claim_mismatch_wrong_doctype(
    session: Session, held: HeldCircuit, config: Config
) -> None:
    body = _body(session, _device_response(held, _anchor_cert()[1], docType="other.doctype"))
    verdict = await verify_response(session, held, AnchorSet(()), body, config)
    assert verdict == VerdictFailed(state="failed", reason="claim-mismatch")


async def test_claim_mismatch_claim_not_disclosed(
    session: Session, held: HeldCircuit, config: Config
) -> None:
    disclosed = {DOC_TYPE: [{"elementIdentifier": "age_over_18", "elementValue": False}]}
    body = _body(session, _device_response(held, _anchor_cert()[1], issuerSigned=disclosed))
    verdict = await verify_response(session, held, AnchorSet(()), body, config)
    assert verdict == VerdictFailed(state="failed", reason="claim-mismatch")


async def test_claim_mismatch_namespace_absent(
    session: Session, held: HeldCircuit, config: Config
) -> None:
    body = _body(session, _device_response(held, _anchor_cert()[1], issuerSigned={}))
    verdict = await verify_response(session, held, AnchorSet(()), body, config)
    assert verdict == VerdictFailed(state="failed", reason="claim-mismatch")


async def test_stale_proof(session: Session, held: HeldCircuit, config: Config) -> None:
    stale = datetime.now(UTC) - timedelta(hours=1)
    cert, chain = _anchor_cert()
    body = _body(session, _device_response(held, chain, timestamp=stale))
    verdict = await verify_response(session, held, AnchorSet((cert,)), body, config)
    assert verdict == VerdictFailed(state="failed", reason="stale-proof")


async def test_untrusted_issuer(session: Session, held: HeldCircuit, config: Config) -> None:
    body = _body(session, _device_response(held, _anchor_cert()[1]))
    verdict = await verify_response(session, held, AnchorSet(()), body, config)
    assert verdict == VerdictFailed(state="failed", reason="untrusted-issuer")


async def test_proof_invalid(
    session: Session, held: HeldCircuit, config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    cert, chain = _anchor_cert()

    def _raise(*_a: object, **_k: object) -> None:
        raise mdoc.VerifierError(mdoc.VerifierErrorCode.MDOC_VERIFIER_GENERAL_FAILURE)

    monkeypatch.setattr(held.longfellow, "verify", _raise)
    body = _body(session, _device_response(held, chain))
    verdict = await verify_response(session, held, AnchorSet((cert,)), body, config)
    assert verdict == VerdictFailed(state="failed", reason="proof-invalid")


async def test_malformed_inner_document_data(
    session: Session, held: HeldCircuit, config: Config
) -> None:
    document = {"proof": b"proof-bytes", "documentData": cbor2.CBORTag(24, b"\xa1\x00")}
    plaintext = cbor2.dumps({"version": "1.0", "status": 0, "zkDocuments": [document]})
    body = _body(session, plaintext)
    verdict = await verify_response(session, held, AnchorSet(()), body, config)
    assert verdict == VerdictFailed(state="failed", reason="invalid-envelope")


async def test_naive_timestamp(session: Session, held: HeldCircuit, config: Config) -> None:
    # A tag-0 string without an offset decodes to a timezone-naive datetime.
    naive = cbor2.CBORTag(0, "2026-01-15T09:00:00")
    body = _body(session, _device_response(held, _anchor_cert()[1], timestamp=naive))
    verdict = await verify_response(session, held, AnchorSet(()), body, config)
    assert verdict == VerdictFailed(state="failed", reason="invalid-envelope")


async def test_engine_error(
    session: Session, held: HeldCircuit, config: Config, monkeypatch: pytest.MonkeyPatch
) -> None:
    cert, chain = _anchor_cert()

    def _boom(*_a: object, **_k: object) -> None:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(held.longfellow, "verify", _boom)
    body = _body(session, _device_response(held, chain))
    verdict = await verify_response(session, held, AnchorSet((cert,)), body, config)
    assert verdict == VerdictFailed(state="failed", reason="engine-error")


async def test_a_photo_id_verifies_with_its_own_doctype_and_namespace(
    session: Session, held: HeldCircuit, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "photo-config.toml"
    path.write_text(render_config(credential=["eu-av", "iso-mdl", "photo-id"]))
    config = load_config(path)
    cert, chain = _anchor_cert()
    seen: dict[str, object] = {}

    def _record(*args: object, **_kwargs: object) -> None:
        seen["doc_type"] = args[5]
        seen["requested"] = args[2]

    monkeypatch.setattr(mdoc, "RequestedAttribute", lambda *fields: fields)
    monkeypatch.setattr(held.longfellow, "verify", _record)
    response = _device_response(
        held,
        chain,
        docType=PHOTO_ID.doc_type,
        issuerSigned={
            PHOTO_ID.namespace: [{"elementIdentifier": "age_over_18", "elementValue": True}]
        },
    )
    verdict = await verify_response(
        session, held, AnchorSet((cert,)), _body(session, response), config
    )
    assert isinstance(verdict, VerdictVerified)
    assert seen["doc_type"] == PHOTO_ID.doc_type
    assert seen["requested"] == [(PHOTO_ID.namespace, "age_over_18", cbor2.dumps(True))]
