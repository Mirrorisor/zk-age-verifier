import hashlib
from typing import Any

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from pylongfellow.mdoc import CircuitSpec

from zk_age_verifier.core.constants import EU_AV, ISO_MDL
from zk_age_verifier.core.encoding import b64url_decode, b64url_encode
from zk_age_verifier.core.engine.circuits import HeldCircuit, zk_system_id
from zk_age_verifier.core.transport.dc import (
    COSE_CRV,
    COSE_CRV_P256,
    COSE_KTY,
    COSE_KTY_EC2,
    COSE_X,
    COSE_Y,
    DcTransport,
    DecryptFailed,
    InvalidEnvelope,
    build_dc_request,
    build_device_request,
    build_encryption_info,
    build_handover_hash,
    build_session_transcript,
    open_response,
    parse_response_wrapper,
    seal_response,
)

NONCE = bytes(range(16))

# Pinned output of build_encryption_info(NONCE, <key from conftest SECRET>) so
# unintended byte drift fails a test; the structure test below proves the pin
# was correct when committed. Regenerate on intentional emission changes.
EXPECTED_ENCRYPTION_INFO = bytes.fromhex(
    "82656463617069a2656e6f6e636550000102030405060708090a0b0c0d0e0f7272"
    "6563697069656e745075626c69634b6579a42258204536be3a50f318fbf9a54759"
    "02a221502bef0d57e08c53b2cc0a56f17d9f9354215820515c3d6eb9e396b904d3"
    "feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f20010102"
)


def test_encryption_info_matches_pinned_bytes(recipient_key: ec.EllipticCurvePublicKey) -> None:
    assert build_encryption_info(NONCE, recipient_key) == EXPECTED_ENCRYPTION_INFO


def test_encryption_info_structure(recipient_key: ec.EllipticCurvePublicKey) -> None:
    decoded = cbor2.loads(EXPECTED_ENCRYPTION_INFO)
    assert decoded[0] == "dcapi"
    body = decoded[1]
    assert body["nonce"] == NONCE
    numbers = recipient_key.public_numbers()
    assert body["recipientPublicKey"] == {
        COSE_KTY: COSE_KTY_EC2,
        COSE_CRV: COSE_CRV_P256,
        COSE_X: numbers.x.to_bytes(32, "big"),
        COSE_Y: numbers.y.to_bytes(32, "big"),
    }


def test_device_request_decode_back(spec: CircuitSpec) -> None:
    zsid = zk_system_id(spec)
    decoded = cbor2.loads(build_device_request(spec, zsid, ["age_over_18"]))
    assert set(decoded.keys()) == {"version", "docRequests"}
    assert decoded["version"] == "1.1"

    doc_requests = decoded["docRequests"]
    assert len(doc_requests) == 1
    entry = doc_requests[0]
    assert "readerAuth" not in entry

    items = entry["itemsRequest"]
    assert isinstance(items, cbor2.CBORTag)
    assert items.tag == 24
    items_map = cbor2.loads(items.value)
    assert items_map["docType"] == "eu.europa.ec.av.1"
    namespace = items_map["nameSpaces"]["eu.europa.ec.av.1"]
    assert namespace == {"age_over_18": False}  # intentToRetain

    # requestInfo INSIDE the tag-24 itemsRequest — the only location the shipped
    # wallet reads (observed 2026-07-14); a DocRequest-level sibling is ignored.
    assert set(entry.keys()) == {"itemsRequest"}
    zk_request = items_map["requestInfo"]["zkRequest"]
    assert zk_request["zkRequired"] is True
    system_specs = zk_request["systemSpecs"]
    assert len(system_specs) == 1
    system_spec = system_specs[0]
    assert system_spec["zkSystemId"] == zsid
    assert system_spec["system"] == spec.system
    assert system_spec["params"] == {
        "version": spec.version,
        "circuit_hash": spec.circuit_hash,
        "num_attributes": spec.num_attributes,
        "block_enc_hash": spec.block_enc_hash,
        "block_enc_sig": spec.block_enc_sig,
    }


def test_dc_request_shape() -> None:
    dc_request = build_dc_request(b"\x01\x02", b"\x03\x04")
    assert set(dc_request.keys()) == {"digital", "mediation"}
    assert dc_request["mediation"] == "required"

    digital = dc_request["digital"]
    assert isinstance(digital, dict)
    assert set(digital.keys()) == {"requests"}
    requests = digital["requests"]
    assert isinstance(requests, list)
    assert len(requests) == 1
    request = requests[0]
    assert set(request.keys()) == {"protocol", "data"}
    assert request["protocol"] == "org-iso-mdoc"

    data = request["data"]
    assert set(data.keys()) == {"deviceRequest", "encryptionInfo"}
    assert "=" not in data["deviceRequest"]
    assert "=" not in data["encryptionInfo"]
    assert b64url_decode(data["deviceRequest"]) == b"\x01\x02"
    assert b64url_decode(data["encryptionInfo"]) == b"\x03\x04"


def test_device_request_names_the_iso_licence_namespace_apart_from_its_doctype(
    spec: CircuitSpec,
) -> None:
    decoded = cbor2.loads(build_device_request(spec, zk_system_id(spec), ["age_over_18"], ISO_MDL))
    items = cbor2.loads(decoded["docRequests"][0]["itemsRequest"].value)
    assert items["docType"] == "org.iso.18013.5.1.mDL"
    assert items["nameSpaces"] == {"org.iso.18013.5.1": {"age_over_18": False}}


def test_device_request_defaults_to_the_eu_profile(spec: CircuitSpec) -> None:
    explicit = build_device_request(spec, "zsid", ["age_over_18"], EU_AV)
    assert build_device_request(spec, "zsid", ["age_over_18"]) == explicit


def test_claim_count_guard(spec: CircuitSpec) -> None:
    with pytest.raises(ValueError, match="claim count"):
        build_device_request(spec, "zsid", [])


def test_build_offer_state_and_request(held: HeldCircuit) -> None:
    state, offer = DcTransport(held, EU_AV).build_offer(["age_over_18"])

    assert offer["mediation"] == "required"
    digital = offer["digital"]
    assert isinstance(digital, dict)
    requests = digital["requests"]
    assert isinstance(requests, list)
    data = requests[0]["data"]
    assert state.encryption_info_b64 == data["encryptionInfo"]

    cose_key = cbor2.loads(b64url_decode(state.encryption_info_b64))[1]["recipientPublicKey"]
    numbers = state.private_key.public_key().public_numbers()
    assert cose_key[COSE_X] == numbers.x.to_bytes(32, "big")


ENCRYPTION_INFO_B64 = "ZW5jcnlwdGlvbi1pbmZv"
ORIGIN = "https://chat.example.org"

# Pinned output of build_session_transcript(ENCRYPTION_INFO_B64, ORIGIN) so
# unintended byte drift fails a test; the structure test below proves the pin
# was correct when committed. Regenerate on intentional emission changes.
EXPECTED_TRANSCRIPT = bytes.fromhex(
    "83f6f6826564636170695820217b8a9b5540f09b43d6ae2a62b0fd44593bced4fde7ff3e54947fcc4cc109e4"
)


def test_transcript_matches_pinned_bytes() -> None:
    assert build_session_transcript(ENCRYPTION_INFO_B64, ORIGIN) == EXPECTED_TRANSCRIPT


def test_transcript_structure() -> None:
    decoded = cbor2.loads(EXPECTED_TRANSCRIPT)
    assert decoded[0] is None
    assert decoded[1] is None
    handover = decoded[2]
    assert handover[0] == "dcapi"
    assert handover[1] == hashlib.sha256(cbor2.dumps([ENCRYPTION_INFO_B64, ORIGIN])).digest()


def test_transcript_binds_origin() -> None:
    other = build_session_transcript(ENCRYPTION_INFO_B64, "https://evil.example.org")
    assert other != EXPECTED_TRANSCRIPT


def test_handover_hash_matches_transcript_digest() -> None:
    decoded = cbor2.loads(EXPECTED_TRANSCRIPT)
    assert build_handover_hash(ENCRYPTION_INFO_B64, ORIGIN) == decoded[2][1]


SEAL_TRANSCRIPT = b"session-transcript-bytes"
PLAINTEXT = b"the device response"


def test_round_trip() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    enc, ciphertext = seal_response(PLAINTEXT, private_key.public_key(), SEAL_TRANSCRIPT)
    assert open_response(enc, ciphertext, private_key, SEAL_TRANSCRIPT) == PLAINTEXT


def test_wrong_transcript_fails() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    enc, ciphertext = seal_response(PLAINTEXT, private_key.public_key(), SEAL_TRANSCRIPT)
    with pytest.raises(DecryptFailed):
        open_response(enc, ciphertext, private_key, b"a different transcript")


def test_wrong_key_fails() -> None:
    sealed_to = ec.generate_private_key(ec.SECP256R1())
    other = ec.generate_private_key(ec.SECP256R1())
    enc, ciphertext = seal_response(PLAINTEXT, sealed_to.public_key(), SEAL_TRANSCRIPT)
    with pytest.raises(DecryptFailed):
        open_response(enc, ciphertext, other, SEAL_TRANSCRIPT)


def _wrapper(enc: object = b"enc-key", ciphertext: object = b"ciphertext") -> dict[str, object]:
    return {
        "response": b64url_encode(cbor2.dumps(["dcapi", {"enc": enc, "cipherText": ciphertext}]))
    }


def test_parse_wrapper_happy() -> None:
    assert parse_response_wrapper(_wrapper()) == (b"enc-key", b"ciphertext")


def test_parse_wrapper_response_not_string() -> None:
    with pytest.raises(InvalidEnvelope):
        parse_response_wrapper({"response": 5})


def test_parse_wrapper_not_cbor() -> None:
    with pytest.raises(InvalidEnvelope):
        parse_response_wrapper({"response": b64url_encode(b"\x9f")})


def test_parse_wrapper_wrong_discriminator() -> None:
    with pytest.raises(InvalidEnvelope):
        parse_response_wrapper({"response": b64url_encode(cbor2.dumps(["nope", {}]))})


def test_parse_wrapper_missing_fields() -> None:
    with pytest.raises(InvalidEnvelope):
        parse_response_wrapper(_wrapper(ciphertext="not-bytes"))


def test_build_offer_asks_for_the_credential_the_transport_was_given(held: HeldCircuit) -> None:
    _, offer = DcTransport(held, ISO_MDL).build_offer(["age_over_18"])
    digital = offer["digital"]
    assert isinstance(digital, dict)
    device_request = cbor2.loads(b64url_decode(digital["requests"][0]["data"]["deviceRequest"]))
    items = cbor2.loads(device_request["docRequests"][0]["itemsRequest"].value)
    assert items["docType"] == ISO_MDL.doc_type
    assert list(items["nameSpaces"]) == [ISO_MDL.namespace]


def _doc_requests(device_request: Any) -> list[Any]:
    return [cbor2.loads(d["itemsRequest"].value) for d in device_request["docRequests"]]


def test_a_single_profile_sends_no_device_request_info(spec: CircuitSpec) -> None:
    decoded = cbor2.loads(build_device_request(spec, "zsid", ["age_over_18"], ISO_MDL))
    assert "deviceRequestInfo" not in decoded
    assert len(decoded["docRequests"]) == 1


def test_several_profiles_become_one_choice_for_the_holder(spec: CircuitSpec) -> None:
    decoded = cbor2.loads(build_device_request(spec, "zsid", ["age_over_18"], [EU_AV, ISO_MDL]))
    assert decoded["version"] == "1.1"
    items = _doc_requests(decoded)
    assert [i["docType"] for i in items] == [EU_AV.doc_type, ISO_MDL.doc_type]
    assert [list(i["nameSpaces"]) for i in items] == [[EU_AV.namespace], [ISO_MDL.namespace]]
    assert all(i["requestInfo"]["zkRequest"]["zkRequired"] is True for i in items)
    info = decoded["deviceRequestInfo"]
    assert isinstance(info, cbor2.CBORTag) and info.tag == 24
    assert cbor2.loads(info.value) == {
        "useCases": [{"mandatory": True, "documentSets": [[0], [1]]}]
    }


def test_a_device_request_needs_a_profile(spec: CircuitSpec) -> None:
    with pytest.raises(ValueError, match="at least one credential profile"):
        build_device_request(spec, "zsid", ["age_over_18"], [])


def test_build_offer_asks_for_every_profile_in_one_request(held: HeldCircuit) -> None:
    _, offer = DcTransport(held, (EU_AV, ISO_MDL)).build_offer(["age_over_18"])
    digital = offer["digital"]
    assert isinstance(digital, dict)
    assert len(digital["requests"]) == 1
    device_request = cbor2.loads(b64url_decode(digital["requests"][0]["data"]["deviceRequest"]))
    assert [i["docType"] for i in _doc_requests(device_request)] == [
        EU_AV.doc_type,
        ISO_MDL.doc_type,
    ]
