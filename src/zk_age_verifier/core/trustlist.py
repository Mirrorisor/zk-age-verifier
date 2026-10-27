"""Trust anchors: resolve a presented DS certificate to an issuer public key.

Every configured source collapses at startup into one set of anchor
certificates. A presented certificate is accepted if it is one of those anchors
(fingerprint match) or was directly issued by one; either way its P-256 public
key coordinates are returned, the only value the trust layer feeds the proof
check. The credential's own issuer signature is validated inside the ZK proof.
This module only decides which issuer key the proof is allowed to satisfy.

ETSI list handling extracts certificates from the XML and stops there: TSL
semantics and XAdES signature validation are out of scope, so an ETSI source is
trusted by its pinned path or URL, not by a checked list signature.
"""

import base64
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit
from urllib.request import urlopen
from xml.etree import ElementTree

import structlog
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from zk_age_verifier.config import ConfigError, TrustSource

log = structlog.get_logger(__name__)


class UntrustedIssuer(Exception):
    """Raised when a presented certificate resolves to no trusted anchor."""


@dataclass(frozen=True)
class AnchorSet:
    """A resolved set of trust anchors.

    Attributes:
        anchors: The trusted certificates.
    """

    anchors: tuple[x509.Certificate, ...]

    def resolve(self, cert: x509.Certificate) -> tuple[int, int]:
        """Return the issuer key of a presented certificate the anchors vouch for.

        The certificate is accepted if it is itself an anchor (SHA-256
        fingerprint match) or was directly issued by one, and is within its own
        validity window in either case. A presented certificate must carry a
        keyUsage extension asserting digitalSignature; an anchor accepted as the
        issuer of a chained leaf must assert keyCertSign.

        Args:
            cert: The presented DS certificate from the proof's ``msoX5chain``.

        Returns:
            The issuer P-256 public key as ``(x, y)``.

        Raises:
            UntrustedIssuer: No anchor accepts the certificate, or its key is
                not P-256.
        """
        if not self._accepts(cert):
            _log_untrusted(cert, "no anchor accepts the presented certificate")
            raise UntrustedIssuer("no anchor accepts the presented certificate")
        public_key = cert.public_key()
        if not (
            isinstance(public_key, ec.EllipticCurvePublicKey)
            and isinstance(public_key.curve, ec.SECP256R1)
        ):
            _log_untrusted(cert, "presented certificate key is not P-256")
            raise UntrustedIssuer("presented certificate key is not P-256")
        numbers = public_key.public_numbers()
        return numbers.x, numbers.y

    def _accepts(self, cert: x509.Certificate) -> bool:
        """Report whether an anchor vouches for a certificate within its validity."""
        now = datetime.now(UTC)
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            return False
        if not _key_usage_permits(cert, "digital_signature"):
            return False
        fingerprint = cert.fingerprint(hashes.SHA256())
        if any(fingerprint == anchor.fingerprint(hashes.SHA256()) for anchor in self.anchors):
            return True
        for anchor in self.anchors:
            if not _key_usage_permits(anchor, "key_cert_sign"):
                continue
            try:
                cert.verify_directly_issued_by(anchor)
            except (ValueError, TypeError, InvalidSignature):
                continue
            return True
        return False


def explain_certificate(anchors: AnchorSet, cert: x509.Certificate) -> tuple[bool, list[str]]:
    """Describe, check by check, whether a presented certificate would be trusted.

    This repeats the checks ``AnchorSet.resolve`` makes, but reports every one
    instead of stopping at the first failure, so an operator can see which one
    fails. It is for diagnosis (``--check-cert``); the service itself uses
    ``resolve``.

    Args:
        anchors: The configured anchors.
        cert: The certificate to examine, as a wallet would present it.

    Returns:
        Whether ``resolve`` would accept it, and the report, one line per check.
    """
    now = datetime.now(UTC)
    fingerprint = cert.fingerprint(hashes.SHA256())
    in_window = cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
    signs = _key_usage_permits(cert, "digital_signature")
    public_key = cert.public_key()
    p256 = isinstance(public_key, ec.EllipticCurvePublicKey) and isinstance(
        public_key.curve, ec.SECP256R1
    )
    is_anchor = any(
        fingerprint == anchor.fingerprint(hashes.SHA256()) for anchor in anchors.anchors
    )
    lines = [
        f"certificate: {cert.subject.rfc4514_string()}",
        f"issuer:      {cert.issuer.rfc4514_string()}",
        f"sha256:      {fingerprint.hex()}",
        f"valid {cert.not_valid_before_utc:%Y-%m-%d} to {cert.not_valid_after_utc:%Y-%m-%d}: "
        + ("ok, valid now" if in_window else "NO, not valid today"),
        "keyUsage digitalSignature: " + ("yes" if signs else "NO (missing or not asserted)"),
        "public key is P-256: " + ("yes" if p256 else "NO"),
        "is itself a configured anchor: " + ("yes" if is_anchor else "no"),
        f"configured anchors ({len(anchors.anchors)}):",
    ]
    issued = False
    for anchor in anchors.anchors:
        can_sign = _key_usage_permits(anchor, "key_cert_sign")
        try:
            cert.verify_directly_issued_by(anchor)
            verdict = "signed this certificate"
            issued = issued or can_sign
        except (ValueError, TypeError, InvalidSignature) as exc:
            verdict = "did not sign it (" + (str(exc) or type(exc).__name__) + ")"
        lines.append(
            f"  - {anchor.subject.rfc4514_string()}: {verdict}; "
            + ("may sign certificates" if can_sign else "keyCertSign NOT asserted")
        )
    accepted = in_window and signs and p256 and (is_anchor or issued)
    lines.append("verdict: " + ("TRUSTED" if accepted else "NOT TRUSTED"))
    return accepted, lines


def read_certificate(path: str) -> x509.Certificate:
    """Read one certificate from a PEM or DER file (the first one, for a PEM bundle).

    Raises:
        ConfigError: The file cannot be read or holds no certificate.
    """
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read certificate file {path}: {exc}") from exc
    try:
        return x509.load_pem_x509_certificates(data)[0]
    except ValueError:
        pass
    try:
        return x509.load_der_x509_certificate(data)
    except ValueError as exc:
        raise ConfigError(f"{path} does not contain a PEM or DER certificate") from exc


def _log_untrusted(cert: x509.Certificate, reason: str) -> None:
    """Log which certificate was refused, so an operator can tell why.

    The verdict a client sees stays the bare ``untrusted-issuer``; this detail
    goes to the server log only. It names the presented certificate and its
    SHA-256 fingerprint, which is what an operator compares against the anchors
    they configured (https://github.com/pipe23-org/zk-age-verifier/issues/76).
    """
    log.warning(
        "untrusted_issuer",
        reason=reason,
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        sha256=cert.fingerprint(hashes.SHA256()).hex(),
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=cert.not_valid_after_utc.isoformat(),
    )


def _key_usage_permits(cert: x509.Certificate, bit: str) -> bool:
    """Report whether a certificate's keyUsage extension asserts the named bit.

    A certificate carrying no keyUsage extension asserts nothing.

    Args:
        cert: The certificate to inspect.
        bit: The ``KeyUsage`` attribute name, e.g. ``"digital_signature"``.

    Returns:
        Whether the extension is present and asserts the bit.
    """
    try:
        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
    except x509.ExtensionNotFound:
        return False
    except ValueError as exc:
        # https://github.com/pipe23-org/zk-age-verifier/issues/35
        log.warning(
            "key_usage_der_fallback",
            subject=cert.subject.rfc4514_string(),
            error=str(exc),
        )
        try:
            return _key_usage_from_tbs(cert.tbs_certificate_bytes, bit)
        except Exception as walker_exc:
            log.warning(
                "key_usage_unreadable",
                subject=cert.subject.rfc4514_string(),
                error=str(walker_exc),
            )
            return False
    return bool(getattr(key_usage.value, bit))


# The rest of this block (both constants, _key_usage_from_tbs, _read_tlv)
# exists only while the AV PKI ships certificates whose extensions cannot be
# parsed. When issue #35 closes, delete the block and the ValueError branch in
# _key_usage_permits.

# The keyUsage extension's OID (2.5.29.15) as a complete DER OBJECT IDENTIFIER.
_KEY_USAGE_OID_DER = b"\x06\x03\x55\x1d\x0f"
# KeyUsage BIT STRING positions, per RFC 5280 section 4.2.1.3.
_KEY_USAGE_BIT_INDEX = {"digital_signature": 0, "key_cert_sign": 5}


def _key_usage_from_tbs(tbs: bytes, bit: str) -> bool:
    """Read a keyUsage bit directly from the DER of a TBSCertificate.

    Reading ``Certificate.extensions`` materialises every extension, so one
    malformed extension makes keyUsage unreachable through the normal API. This
    walk decodes only the keyUsage extension. An absent extensions block or
    keyUsage extension asserts nothing, matching the ``ExtensionNotFound``
    branch above.

    Args:
        tbs: The certificate's ``tbs_certificate_bytes``.
        bit: The ``KeyUsage`` attribute name, e.g. ``"digital_signature"``.

    Returns:
        Whether the keyUsage extension is present and asserts the bit.
    """
    _, fields, _ = _read_tlv(tbs, 0)
    offset = 0
    while offset < len(fields):
        tag, extensions, offset = _read_tlv(fields, offset)
        if tag == 0xA3:  # the [3] EXPLICIT extensions field
            break
    else:
        return False
    _, extension_list, _ = _read_tlv(extensions, 0)
    offset = 0
    while offset < len(extension_list):
        _, extension, offset = _read_tlv(extension_list, offset)
        if extension.startswith(_KEY_USAGE_OID_DER):
            break
    else:
        return False
    tag, value, after = _read_tlv(extension, len(_KEY_USAGE_OID_DER))
    if tag == 0x01:  # the critical BOOLEAN is omitted when false
        tag, value, after = _read_tlv(extension, after)
    _, bit_string, _ = _read_tlv(value, 0)
    # BIT STRING content: one octet counting unused trailing bits, then the bits
    # most significant first. DER drops trailing zero bits, so a position past
    # the end is an unasserted bit.
    bits = bit_string[1:]
    octet, position = divmod(_KEY_USAGE_BIT_INDEX[bit], 8)
    if octet >= len(bits):
        return False
    return bool(bits[octet] & (0x80 >> position))


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Read the DER element at ``offset``; return its tag, content, and end offset."""
    tag = data[offset]
    length = data[offset + 1]
    offset += 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    return tag, data[offset : offset + length], offset + length


def load_anchors(sources: list[TrustSource]) -> AnchorSet:
    """Collapse every trust source into one anchor set.

    Args:
        sources: The configured trust sources.

    Returns:
        The combined anchor set.

    Raises:
        ConfigError: The configured sources resolve to zero anchors — an empty
            set would boot cleanly and then reject every presentation.
    """
    anchors: list[x509.Certificate] = []
    for source in sources:
        if source.pem is not None:
            anchors.extend(_load_pem(source.pem))
        else:
            anchors.extend(_load_etsi_xml(cast(str, source.etsi_xml), source.etsi_xml_sha256))
    if not anchors:
        raise ConfigError("trust sources resolved to no anchors; check the [trust] source paths")
    return AnchorSet(tuple(anchors))


def _load_pem(location: str) -> list[x509.Certificate]:
    """Load anchors from a PEM file or a directory of ``*.pem`` files."""
    path = Path(location)
    files = sorted(path.glob("*.pem")) if path.is_dir() else [path]
    anchors: list[x509.Certificate] = []
    for file in files:
        anchors.extend(x509.load_pem_x509_certificates(file.read_bytes()))
    return anchors


# ETSI service statuses whose certificates are trusted; every other status (withdrawn,
# deprecated, revoked, ...) is skipped. A service with no status is skipped too.
_ACTIVE_SERVICE_STATUSES = frozenset({"granted", "recognisedatnationallevel"})


def _load_etsi_xml(location: str, pinned_sha256: str | None = None) -> list[x509.Certificate]:
    """Fetch and parse an ETSI list from a path or URL, extracting its service certificates.

    The list's own signature is not verified. Pin the file's SHA-256 with
    ``pinned_sha256`` to make sure it is the file the operator reviewed.

    Raises:
        ConfigError: The location is an ``http`` URL. A trust list fetched
            over plain http can be replaced in transit, so only ``https``
            URLs and local file paths are accepted. Also raised when
            ``pinned_sha256`` is given and the list's SHA-256 differs.
    """
    scheme = urlsplit(location).scheme
    if scheme == "http":
        raise ConfigError(
            f"trust source url uses scheme {scheme!r}; https or a file path is required"
        )
    if scheme == "https":
        with urlopen(location) as response:  # noqa: S310 - operator-configured startup fetch
            data = response.read()
    else:
        data = Path(location).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if pinned_sha256 is None:
        log.warning("etsi_xml_not_pinned", location=location, sha256=digest)
    elif digest != pinned_sha256.lower():
        raise ConfigError(
            f"trust list {location} has SHA-256 {digest}, not the pinned {pinned_sha256.lower()}"
        )
    root = ElementTree.fromstring(data)
    anchors: list[x509.Certificate] = []
    # Only the certificates a service is listed under are anchors. The list's
    # own signer certificate (in ds:Signature) and the certificates of past
    # service versions (ServiceHistory) are in the same file but are not
    # anchors. https://github.com/pipe23-org/zk-age-verifier/issues/76
    for information in root.iter():
        if _local_name(information.tag) != "ServiceInformation":
            continue
        status = _service_status(information)
        if status not in _ACTIVE_SERVICE_STATUSES:
            log.warning("etsi_service_skipped", status=status)
            continue
        for identity in information:
            if _local_name(identity.tag) != "ServiceDigitalIdentity":
                continue
            for element in identity.iter():
                if _local_name(element.tag) == "X509Certificate" and element.text:
                    der = base64.b64decode("".join(element.text.split()))
                    anchors.append(x509.load_der_x509_certificate(der))
    return anchors


def _service_status(information: ElementTree.Element) -> str:
    """Return the last path segment of a service's ``ServiceStatus`` URI, or ``""``."""
    for child in information:
        if _local_name(child.tag) == "ServiceStatus":
            return "".join((child.text or "").split()).rsplit("/", 1)[-1]
    return ""


def _local_name(tag: str) -> str:
    """Return an XML tag without its ``{namespace}`` prefix."""
    return tag.rsplit("}", 1)[-1]
