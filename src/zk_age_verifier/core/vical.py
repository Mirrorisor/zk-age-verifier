"""Issuer root certificates from a VICAL (ISO/IEC 18013-5, Annex C).

A VICAL (Verified Issuer Certificate Authority List) is how mobile driving licence
programmes share their issuers' root certificates (IACAs): a CBOR list, signed as a
COSE_Sign1 message by a VICAL signer whose certificate travels in the ``x5chain``
header. AAMVA publishes one for US states, and Austroads is building one for Australia.

Trust passes from one certificate the operator configures: the signer's certificate
must be that certificate or be issued directly by it, the signature must verify, and
the list must not be past its ``nextUpdate`` or ``notAfter``. Only the issuers listed
for the chosen document types (and, optionally, countries) become anchors.
"""

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, cast

import cbor2
import structlog
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from zk_age_verifier.config import ConfigError

log = structlog.get_logger()

_COSE_SIGN1_TAG = 18
_HEADER_ALG = 1
_HEADER_X5CHAIN = 33
# COSE algorithm identifiers (RFC 9053) for ECDSA, the only kind ISO 18013-5 allows.
_ALGORITHMS: dict[int, type[hashes.HashAlgorithm]] = {
    -7: hashes.SHA256,
    -35: hashes.SHA384,
    -36: hashes.SHA512,
}


def load_vical(
    data: bytes,
    trusted: x509.Certificate,
    doc_types: list[str],
    countries: list[str] | None,
    location: str,
) -> list[x509.Certificate]:
    """Verify a VICAL and return the issuer certificates listed for ``doc_types``.

    Args:
        data: The VICAL file, a COSE_Sign1 message (tagged or not).
        trusted: The VICAL signer's certificate, or the certificate that issued it.
        doc_types: Only issuers listed for at least one of these document types load.
        countries: When given, only issuers whose ``issuingCountry`` is one of these
            two-letter codes load.
        location: Where the list came from, for messages.

    Raises:
        ConfigError: The file is not a COSE_Sign1 message, its signer is not
            ``trusted`` or issued by it, the signature does not verify, the list is
            past its ``nextUpdate`` or ``notAfter``, or no issuer matches.
    """
    protected, unprotected, payload, signature = _sign1_parts(data, location)
    header = _decode_map(protected, "protected header", location) if protected else {}
    alg = header.get(_HEADER_ALG)
    algorithm = _ALGORITHMS.get(alg) if isinstance(alg, int) else None
    if algorithm is None:
        raise ConfigError(f"VICAL {location} is not signed with ES256, ES384 or ES512")
    signer = _signer(header.get(_HEADER_X5CHAIN, unprotected.get(_HEADER_X5CHAIN)), location)
    _check_signer(signer, trusted, location)
    _check_signature(signer, algorithm, protected, payload, signature, location)
    content = _decode_map(payload, "content", location)
    for field in ("nextUpdate", "notAfter"):
        if field in content and _instant(content[field], field, location) <= datetime.now(UTC):
            raise ConfigError(
                f"VICAL {location} expired: its {field} was {content[field]}; fetch a current list"
            )
    anchors = _issuers(content, set(doc_types), countries, location)
    log.info(
        "vical_loaded",
        location=location,
        provider=content.get("vicalProvider"),
        issue=content.get("vicalIssueID"),
        anchors=len(anchors),
        signer_sha256=signer.fingerprint(hashes.SHA256()).hex(),
    )
    return anchors


def _sign1_parts(data: bytes, location: str) -> tuple[bytes, Mapping[Any, Any], bytes, bytes]:
    """Split a COSE_Sign1 message into its four parts, checking their types.

    cbor2 decodes the inside of an unknown tag (such as COSE_Sign1's 18) as immutable
    containers, so the message may be a tuple and its header a read-only mapping.
    """
    try:
        message = cbor2.loads(data)
    except cbor2.CBORDecodeError as exc:
        raise ConfigError(f"VICAL {location} is not CBOR: {exc}") from exc
    if isinstance(message, cbor2.CBORTag):
        if message.tag != _COSE_SIGN1_TAG:
            raise ConfigError(f"VICAL {location} has CBOR tag {message.tag}, not COSE_Sign1")
        message = message.value
    if not (
        isinstance(message, (list, tuple))
        and len(message) == 4
        and isinstance(message[0], bytes)
        and isinstance(message[1], Mapping)
        and isinstance(message[2], bytes)
        and isinstance(message[3], bytes)
    ):
        raise ConfigError(f"VICAL {location} is not a COSE_Sign1 message with its content")
    return message[0], message[1], message[2], message[3]


def _decode_map(data: bytes, part: str, location: str) -> Mapping[Any, Any]:
    """Decode a CBOR map, or refuse the list."""
    try:
        value = cbor2.loads(data)
    except cbor2.CBORDecodeError as exc:
        raise ConfigError(f"VICAL {location} {part} is not CBOR: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ConfigError(f"VICAL {location} {part} is not a map")
    return value


def _signer(x5chain: object, location: str) -> x509.Certificate:
    """Return the first certificate of an ``x5chain`` header (one bstr or a list)."""
    first = x5chain[0] if isinstance(x5chain, (list, tuple)) and x5chain else x5chain
    if not isinstance(first, bytes):
        raise ConfigError(f"VICAL {location} carries no signer certificate (x5chain)")
    try:
        return x509.load_der_x509_certificate(first)
    except ValueError as exc:
        raise ConfigError(f"VICAL {location} signer certificate is unreadable: {exc}") from exc


def _check_signer(signer: x509.Certificate, trusted: x509.Certificate, location: str) -> None:
    """Require the signer to be ``trusted`` or issued by it, and valid now."""
    now = datetime.now(UTC)
    if not signer.not_valid_before_utc <= now <= signer.not_valid_after_utc:
        raise ConfigError(f"VICAL {location} signer certificate is not valid today")
    if signer.fingerprint(hashes.SHA256()) == trusted.fingerprint(hashes.SHA256()):
        return
    try:
        signer.verify_directly_issued_by(trusted)
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise ConfigError(
            f"VICAL {location} is signed by {signer.subject.rfc4514_string()}, "
            "which is neither the configured vical_signer nor issued by it"
        ) from exc


def _check_signature(
    signer: x509.Certificate,
    algorithm: type[hashes.HashAlgorithm],
    protected: bytes,
    payload: bytes,
    signature: bytes,
    location: str,
) -> None:
    """Verify the COSE_Sign1 signature (raw r || s) over its Sig_structure."""
    key = signer.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ConfigError(f"VICAL {location} signer key is not an elliptic-curve key")
    size = (key.curve.key_size + 7) // 8
    if len(signature) != 2 * size:
        raise ConfigError(f"VICAL {location} signature has the wrong length")
    der = encode_dss_signature(
        int.from_bytes(signature[:size], "big"), int.from_bytes(signature[size:], "big")
    )
    to_be_signed = cbor2.dumps(["Signature1", protected, b"", payload])
    try:
        key.verify(der, to_be_signed, ec.ECDSA(algorithm()))
    except InvalidSignature as exc:
        raise ConfigError(f"VICAL {location} failed its signature check") from exc


def _instant(value: object, field: str, location: str) -> datetime:
    """Read a CBOR date (``tdate``, decoded or as text) as an aware datetime."""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            pass
    if not isinstance(value, datetime):
        raise ConfigError(f"VICAL {location} has a {field} that is not a date and time")
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _issuers(
    content: Mapping[Any, Any], doc_types: set[str], countries: list[str] | None, location: str
) -> list[x509.Certificate]:
    """Return the listed issuer certificates that match the chosen types and countries."""
    entries = content.get("certificateInfos")
    if not isinstance(entries, (list, tuple)):
        raise ConfigError(f"VICAL {location} has no certificateInfos list")
    wanted_countries = {country.upper() for country in countries} if countries else None
    anchors: list[x509.Certificate] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        listed = entry.get("docType")
        if not isinstance(listed, (list, tuple)) or not doc_types.intersection(listed):
            continue
        country = entry.get("issuingCountry")
        if wanted_countries is not None and (
            not isinstance(country, str) or country.upper() not in wanted_countries
        ):
            continue
        certificate = entry.get("certificate")
        try:
            anchors.append(x509.load_der_x509_certificate(cast(bytes, certificate)))
        except (ValueError, TypeError):
            log.warning(
                "vical_bad_certificate",
                location=location,
                issuing_authority=entry.get("issuingAuthority"),
            )
    if not anchors:
        raise ConfigError(
            f"VICAL {location} lists no issuer for doc types {sorted(doc_types)}"
            + (f" in {sorted(wanted_countries)}" if wanted_countries else "")
        )
    return anchors
