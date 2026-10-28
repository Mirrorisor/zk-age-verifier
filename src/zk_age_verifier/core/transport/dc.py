"""The Digital Credentials transport: request framing, HPKE envelope, and handover.

This transport builds the ``navigator.credentials.get`` offer and the
``EncryptionInfo`` and ``DeviceRequest`` it carries, builds the
``SessionTranscript`` handover, seals and opens the HPKE response, and parses
the ``dcapi`` response wrapper. It never reads decrypted presentation bytes and
does not import the engine.
"""

import hashlib
import secrets
from collections.abc import Sequence
from dataclasses import dataclass

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey
from pylongfellow.mdoc import CircuitSpec

from zk_age_verifier.core.constants import EU_AV, CredentialProfile
from zk_age_verifier.core.encoding import b64url_decode, b64url_encode
from zk_age_verifier.core.engine.circuits import HeldCircuit

# COSE_Key labels and values (RFC 9052 §7): kty EC2, crv P-256, x/y coordinates.
COSE_KTY, COSE_CRV, COSE_X, COSE_Y = 1, -1, -2, -3
COSE_KTY_EC2 = 2
COSE_CRV_P256 = 1

# P-256 coordinates are fixed-length 32-byte big-endian.
_COORDINATE_BYTES = 32

_NONCE_BYTES = 16


class InvalidEnvelope(Exception):
    """Raised when the response wrapper is malformed."""


class DecryptFailed(Exception):
    """Raised when HPKE open fails, whatever the underlying cause."""


def build_encryption_info(nonce: bytes, recipient_key: ec.EllipticCurvePublicKey) -> bytes:
    """Build the CBOR ``EncryptionInfo`` addressing the response to a session key.

    Args:
        nonce: Per-session random bytes; the transport generates 16.
        recipient_key: The session's ephemeral P-256 public key.

    Returns:
        CBOR bytes of ``["dcapi", {"nonce": ..., "recipientPublicKey": COSE_Key}]``.
    """
    numbers = recipient_key.public_numbers()
    # CBOR maps are order-agnostic (RFC 8949) and no requirement pins this key
    # order. It does not match the reference implementation's writer (multipaz
    # emits kty, crv, x, y). If a wallet ever fails to parse our request and
    # nothing else explains it, try that order first.
    cose_key = {
        COSE_Y: numbers.y.to_bytes(_COORDINATE_BYTES, "big"),
        COSE_X: numbers.x.to_bytes(_COORDINATE_BYTES, "big"),
        COSE_CRV: COSE_CRV_P256,
        COSE_KTY: COSE_KTY_EC2,
    }
    return cbor2.dumps(["dcapi", {"nonce": nonce, "recipientPublicKey": cose_key}])


def build_device_request(
    spec: CircuitSpec,
    zk_system_id: str,
    claims: Sequence[str],
    profile: CredentialProfile = EU_AV,
) -> bytes:
    """Build the CBOR ``DeviceRequest`` carrying the ZK ask.

    Args:
        spec: The held circuit's spec; its fields populate ``params``.
        zk_system_id: The circuit-identity string advertised in ``systemSpecs``.
        claims: Requested claim identifiers, one namespace entry each.
        profile: The credential profile; its doctype and claim namespace are asked for.

    Returns:
        CBOR bytes of the ``DeviceRequest``.

    Raises:
        ValueError: ``len(claims)`` differs from ``spec.num_attributes``; the
            wallet would find no circuit match and fail the request silently.
    """
    if len(claims) != spec.num_attributes:
        raise ValueError(
            f"claim count {len(claims)} must equal spec.num_attributes {spec.num_attributes}"
        )
    system_spec = {
        "zkSystemId": zk_system_id,
        "system": spec.system,
        "params": {
            "version": spec.version,
            "circuit_hash": spec.circuit_hash,
            "num_attributes": spec.num_attributes,
            "block_enc_hash": spec.block_enc_hash,
            "block_enc_sig": spec.block_enc_sig,
        },
    }
    # The ZK ask goes as requestInfo inside the tag-24 itemsRequest, the only
    # place multipaz reads it (DeviceRequest.kt:293, DocRequest.fromDataItem
    # itemsRequest["requestInfo"], both @ 0.99.0; AV profile §A.11 agrees). A
    # DocRequest-level sibling key is never parsed; the wallet then silently
    # falls back to a standard presentation (observed on-device, 2026-07-14).
    items_request = {
        "docType": profile.doc_type,
        "nameSpaces": {profile.namespace: {claim: False for claim in claims}},
        "requestInfo": {"zkRequest": {"systemSpecs": [system_spec], "zkRequired": True}},
    }
    doc_request = {"itemsRequest": cbor2.CBORTag(24, cbor2.dumps(items_request))}
    return cbor2.dumps({"version": "1.1", "docRequests": [doc_request]})


def build_dc_request(device_request: bytes, encryption_info: bytes) -> dict[str, object]:
    """Assemble the ``navigator.credentials.get`` argument.

    The session store keeps ``data.encryptionInfo`` verbatim; the transcript
    hashes that exact string, so it is never re-encoded from the key.

    Args:
        device_request: CBOR ``DeviceRequest`` bytes.
        encryption_info: CBOR ``EncryptionInfo`` bytes.

    Returns:
        The DC-API request dict with both payloads as unpadded base64url strings.
    """
    return {
        "digital": {
            "requests": [
                {
                    "protocol": "org-iso-mdoc",
                    "data": {
                        "deviceRequest": b64url_encode(device_request),
                        "encryptionInfo": b64url_encode(encryption_info),
                    },
                }
            ]
        },
        "mediation": "required",
    }


def build_handover_hash(encryption_info_b64: str, origin: str) -> bytes:
    """Hash the two transcript inputs into the handover digest.

    Args:
        encryption_info_b64: The ``EncryptionInfo`` string exactly as issued;
            never re-encoded from the key.
        origin: The origin asserted in the presentation.

    Returns:
        ``SHA256(CBOR([encryption_info_b64, origin]))``.
    """
    return hashlib.sha256(cbor2.dumps([encryption_info_b64, origin])).digest()


def build_session_transcript(encryption_info_b64: str, origin: str) -> bytes:
    """Build the ``SessionTranscript`` bytes the response proof is bound to.

    The handover hash sits inside the ``dcapi`` handover of the outer
    ``[null, null, [...]]`` structure. The returned bytes feed HPKE ``info``
    directly; they are not hashed again.

    Args:
        encryption_info_b64: The ``EncryptionInfo`` string exactly as issued;
            never re-encoded from the key.
        origin: The origin asserted in the presentation.

    Returns:
        The CBOR bytes of the session transcript.
    """
    handover_hash = build_handover_hash(encryption_info_b64, origin)
    return cbor2.dumps([None, None, ["dcapi", handover_hash]])


def _suite() -> CipherSuite:
    """Build the pinned cipher suite."""
    return CipherSuite.new(KEMId.DHKEM_P256_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM)


def open_response(
    enc: bytes,
    ciphertext: bytes,
    private_key: ec.EllipticCurvePrivateKey,
    transcript: bytes,
) -> bytes:
    """Open an HPKE-sealed response with the session's private key.

    The wrong origin or wrong session yields a transcript that does not match the
    one baked into the ciphertext, so the open fails; this transcript binding is
    what prevents replay. Any pyhpke failure surfaces as ``DecryptFailed``, so
    the caller need not track pyhpke's exception taxonomy.

    Args:
        enc: The HPKE encapsulated key from the response wrapper.
        ciphertext: The AES-128-GCM ciphertext and tag.
        private_key: The session's ephemeral P-256 recipient key.
        transcript: The reconstructed session transcript, used as HPKE ``info``.

    Returns:
        The decrypted plaintext DeviceResponse.

    Raises:
        DecryptFailed: The open failed.
    """
    try:
        recipient = KEMKey.from_pyca_cryptography_key(private_key)
        context = _suite().create_recipient_context(enc, recipient, info=transcript)
        return context.open(ciphertext, aad=b"")
    except Exception as exc:
        raise DecryptFailed("HPKE open failed") from exc


def seal_response(
    plaintext: bytes,
    recipient_key: ec.EllipticCurvePublicKey,
    transcript: bytes,
) -> tuple[bytes, bytes]:
    """Seal a response to the session's public key (the sender's side).

    Args:
        plaintext: The DeviceResponse bytes to seal.
        recipient_key: The session's ephemeral P-256 public key.
        transcript: The session transcript, used as HPKE ``info``.

    Returns:
        The encapsulated key and the ciphertext, as ``(enc, ciphertext)``.
    """
    recipient = KEMKey.from_pyca_cryptography_key(recipient_key)
    enc, context = _suite().create_sender_context(recipient, info=transcript)
    return enc, context.seal(plaintext, aad=b"")


def parse_response_wrapper(data: dict[str, object]) -> tuple[bytes, bytes]:
    """Unwrap the ``{"response": ...}`` object into ``(enc, ciphertext)``.

    Args:
        data: The DigitalCredential ``data`` object relayed by the consumer.

    Returns:
        The HPKE encapsulated key and the ciphertext.

    Raises:
        InvalidEnvelope: The object is not a ``dcapi`` response wrapper.
    """
    response_b64 = data.get("response")
    if not isinstance(response_b64, str):
        raise InvalidEnvelope("response wrapper must carry a 'response' string")
    try:
        wrapper = cbor2.loads(b64url_decode(response_b64))
    except Exception as exc:
        raise InvalidEnvelope("response is not valid base64url CBOR") from exc
    if not (
        isinstance(wrapper, list)
        and len(wrapper) == 2
        and wrapper[0] == "dcapi"
        and isinstance(wrapper[1], dict)
    ):
        raise InvalidEnvelope("response is not a dcapi wrapper")
    body = wrapper[1]
    enc = body.get("enc")
    ciphertext = body.get("cipherText")
    if not (isinstance(enc, bytes) and isinstance(ciphertext, bytes)):
        raise InvalidEnvelope("dcapi wrapper is missing enc or cipherText bytes")
    return enc, ciphertext


@dataclass(frozen=True)
class DcSessionState:
    """Per-session DC transport state, held by the session for its one attempt.

    Attributes:
        private_key: Ephemeral P-256 HPKE recipient key, used once at relay time.
        encryption_info_b64: The ``EncryptionInfo`` string as issued; a transcript input.
    """

    private_key: ec.EllipticCurvePrivateKey
    encryption_info_b64: str


class DcTransport:
    """Builds the DC offer for a session and the transport state it keeps."""

    def __init__(self, held: HeldCircuit, profile: CredentialProfile) -> None:
        """Bind the transport to the circuit and credential every offer asks for.

        Args:
            held: The resolved circuit whose identity every request advertises.
            profile: The credential profile every request asks for.
        """
        self._held = held
        self._profile = profile

    def build_offer(self, claims: Sequence[str]) -> tuple[DcSessionState, dict[str, object]]:
        """Build the ``navigator.credentials.get`` offer and its session state.

        Args:
            claims: The validated check list.

        Returns:
            The per-session transport state and the DC-API request dict.
        """
        private_key = ec.generate_private_key(ec.SECP256R1())
        nonce = secrets.token_bytes(_NONCE_BYTES)
        encryption_info = build_encryption_info(nonce, private_key.public_key())
        device_request = build_device_request(
            self._held.spec, self._held.zk_system_id, claims, self._profile
        )
        offer = build_dc_request(device_request, encryption_info)
        state = DcSessionState(
            private_key=private_key,
            encryption_info_b64=b64url_encode(encryption_info),
        )
        return state, offer
