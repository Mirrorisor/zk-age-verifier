"""Trust anchors: resolve a presented DS certificate to an issuer public key.

Every configured source collapses at startup into one set of anchor
certificates. A presented certificate is accepted if it is one of those anchors
(fingerprint match) or was directly issued by one; either way its P-256 public
key coordinates are returned, the only value the trust layer feeds the proof
check. The credential's own issuer signature is validated inside the ZK proof.
This module only decides which issuer key the proof is allowed to satisfy.

An ETSI list is refused once its NextUpdate has passed. Its XML signature is checked
when the source names the certificates authorised to sign it (``etsi_xml_signers``);
the anchors are then read only from the signed content. Without them, an ETSI source is
trusted by its path or URL alone, and a warning says so.
"""

import base64
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
from lxml.etree import LxmlError
from signxml.exceptions import SignXMLException
from signxml.verifier import SignatureConfiguration, XMLVerifier

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
        validity window in either case. An anchor accepted as the issuer must be
        within its validity window too. A presented certificate must carry a
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
            if not (anchor.not_valid_before_utc <= now <= anchor.not_valid_after_utc):
                continue
            if not _key_usage_permits(anchor, "key_cert_sign"):
                continue
            try:
                cert.verify_directly_issued_by(anchor)
            except (ValueError, TypeError, InvalidSignature):
                continue
            return True
        return False


def _log_untrusted(cert: x509.Certificate, reason: str) -> None:
    """Log which certificate was refused, so an operator can tell why.

    The verdict a client sees stays the bare ``untrusted-issuer``; this detail
    goes to the debug log only. It names the presented certificate and its
    SHA-256 fingerprint, which is what an operator compares against the anchors
    they configured (https://github.com/pipe23-org/zk-age-verifier/issues/76).
    """
    log.debug(
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
            anchors.extend(_load_etsi_xml(cast(str, source.etsi_xml), source.etsi_xml_signers))
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


# Service statuses whose certificates are trusted, by the last segment of the status URI;
# every other status (withdrawn, deprecated, revoked, ...) is skipped, and so is a service
# with no status. "granted" and "recognisedatnationallevel" are the ETSI TS 119 612 ones
# (http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/...); "recognized" is the EU Age
# Verification Trusted List's own
# (http://trust.tech.ec.europa.eu/lists/age-verification/service-status/recognized).
_ACTIVE_SERVICE_STATUSES = frozenset({"granted", "recognisedatnationallevel", "recognized"})

# Service type of a proof-of-age attestation service on the EU Age Verification Trusted List.
_AGE_ATTESTATION_SERVICE_TYPE = (
    "http://trust.tech.ec.europa.eu/lists/age-verification/service-type/paa"
)

# A list is fetched once at startup. A server that stalls, or sends far more than any real
# list, must not hang or bloat the service.
_FETCH_TIMEOUT_SECONDS = 30
_MAX_LIST_BYTES = 16 * 1024 * 1024


def _load_etsi_xml(location: str, signers: str | None = None) -> list[x509.Certificate]:
    """Load the certificates of active age-attestation services from an ETSI list at a path or URL.

    With ``signers`` (a PEM file or a directory of ``*.pem`` files), the list's XML signature
    must verify against one of those certificates, and the anchors are read from the signed
    content only. Without it the signature is not checked and ``etsi_xml_signature_not_checked``
    is logged. Either way a list whose ``NextUpdate`` has passed is refused.

    Raises:
        ConfigError: The location is an ``http`` URL. A trust list fetched
            over plain http can be replaced in transit, so only ``https``
            URLs and local file paths are accepted. Also raised when the signer
            certificates cannot be read, the signature does not verify against any
            of them, the list is past its ``NextUpdate``, or an ``https``
            list cannot be fetched within the timeout or is larger than 16 MiB.
    """
    scheme = urlsplit(location).scheme
    if scheme == "http":
        raise ConfigError(
            f"trust source url uses scheme {scheme!r}; https or a file path is required"
        )
    if scheme == "https":
        try:
            # Operator-configured startup fetch, so S310 (URL scheme audit) does not apply.
            with urlopen(location, timeout=_FETCH_TIMEOUT_SECONDS) as response:  # noqa: S310
                data = response.read(_MAX_LIST_BYTES + 1)
        except OSError as exc:  # URLError, HTTPError and timeouts are all OSErrors
            raise ConfigError(f"cannot fetch trust list {location}: {exc}") from exc
        if len(data) > _MAX_LIST_BYTES:
            raise ConfigError(f"trust list {location} is larger than {_MAX_LIST_BYTES} bytes")
    else:
        data = Path(location).read_bytes()
    if signers is None:
        log.warning("etsi_xml_signature_not_checked", location=location)
        root = ElementTree.fromstring(data)
    else:
        root = _verified_list(data, _read_signers(signers), location)
    _check_next_update(root, location)
    anchors: list[x509.Certificate] = []
    # Only the certificates a service is listed under are anchors. The list's
    # own signer certificate (in ds:Signature) and the certificates of past
    # service versions (ServiceHistory) are in the same file but are not
    # anchors. https://github.com/pipe23-org/zk-age-verifier/issues/76
    for information in root.iter():
        if _local_name(information.tag) != "ServiceInformation":
            continue
        service_type = _service_field(information, "ServiceTypeIdentifier")
        status = _service_field(information, "ServiceStatus").rsplit("/", 1)[-1]
        if service_type != _AGE_ATTESTATION_SERVICE_TYPE or status not in _ACTIVE_SERVICE_STATUSES:
            log.warning("etsi_service_skipped", service_type=service_type, status=status)
            continue
        for identity in information:
            if _local_name(identity.tag) != "ServiceDigitalIdentity":
                continue
            for element in identity.iter():
                if _local_name(element.tag) == "X509Certificate" and element.text:
                    der = base64.b64decode("".join(element.text.split()))
                    anchors.append(x509.load_der_x509_certificate(der))
    return anchors


# A list's signature references its whole content, and XAdES adds one for the signing
# properties. More than a handful is not a real list.
_MAX_SIGNATURE_REFERENCES = 5
_LIST_ROOT = "TrustServiceStatusList"


def _read_signers(location: str) -> list[x509.Certificate]:
    """Read the certificates authorised to sign a list, from a PEM file or directory.

    Raises:
        ConfigError: The file or directory cannot be read, or holds no PEM certificate.
    """
    try:
        signers = _load_pem(location)
    except (OSError, ValueError) as exc:
        raise ConfigError(f"cannot read list signer certificates {location}: {exc}") from exc
    if not signers:
        raise ConfigError(f"list signer certificates {location} hold no certificate")
    return signers


def _children(element: ElementTree.Element, name: str) -> list[ElementTree.Element]:
    """Return an element's direct children with this local name."""
    return [child for child in element if _local_name(child.tag) == name]


def _signature_reference_count(data: bytes, location: str) -> int:
    """Count the references in the list's own ``SignedInfo``.

    The count only tells the verifier how many references to insist on; every one of them
    must verify, so a list cannot gain trust by adding or hiding references.

    Raises:
        ConfigError: The signature carries more references than a real list does.
    """
    signatures = _children(ElementTree.fromstring(data), "Signature")
    signed_infos = _children(signatures[0], "SignedInfo") if signatures else []
    count = len(_children(signed_infos[0], "Reference")) if signed_infos else 1
    if count > _MAX_SIGNATURE_REFERENCES:
        raise ConfigError(f"trust list {location} signature has {count} references; refusing")
    return max(count, 1)


def _verified_list(
    data: bytes, signers: list[x509.Certificate], location: str
) -> ElementTree.Element:
    """Return the list element that a valid signature from one of ``signers`` covers.

    The anchors are read from the signed bytes the verifier returns, not from the
    downloaded file, so unsigned content added around a valid signature is never read.

    Raises:
        ConfigError: The signature does not verify against any of ``signers``, or no
            verified reference covers the whole list.
    """
    failure: Exception | None = None
    for signer in signers:
        try:
            references = _signature_reference_count(data, location)
            verified = XMLVerifier().verify(
                data,
                x509_cert=signer,
                expect_config=SignatureConfiguration(location="./", expect_references=references),
            )
            for result in verified if isinstance(verified, list) else [verified]:
                root = ElementTree.fromstring(result.signed_data)
                if _local_name(root.tag) == _LIST_ROOT:
                    log.info(
                        "etsi_xml_signature_verified",
                        location=location,
                        signer_sha256=signer.fingerprint(hashes.SHA256()).hex(),
                    )
                    return root
        except (SignXMLException, LxmlError, SyntaxError) as exc:
            failure = exc
            continue
        raise ConfigError(
            f"trust list {location} is signed, but no signed part covers the whole list"
        )
    raise ConfigError(f"trust list {location} failed its signature check: {failure}") from failure


def _check_next_update(root: ElementTree.Element, location: str) -> None:
    """Refuse a list whose own ``NextUpdate`` time has passed.

    A list states when its next issue is due; after that moment it is stale, and a stale
    list may be an old copy replayed by someone who wants a withdrawn service trusted
    again. A list without a usable ``NextUpdate`` is accepted with a warning, because
    lists that are not meant to be updated leave it empty.

    Raises:
        ConfigError: The ``NextUpdate`` is not a date and time, or is in the past.
    """
    for element in root.iter():
        if _local_name(element.tag) != "NextUpdate":
            continue
        stamp = "".join("".join(element.itertext()).split())
        if not stamp:
            break
        try:
            due = datetime.fromisoformat(stamp)
        except ValueError as exc:
            raise ConfigError(
                f"trust list {location} has a NextUpdate that is not a date and time: {stamp!r}"
            ) from exc
        if due.tzinfo is None:
            due = due.replace(tzinfo=UTC)
        if due <= datetime.now(UTC):
            raise ConfigError(
                f"trust list {location} expired: its NextUpdate was {stamp}; fetch a current list"
            )
        return
    log.warning("etsi_xml_no_next_update", location=location)


def _service_field(information: ElementTree.Element, name: str) -> str:
    """Return the text of a service's ``name`` child without whitespace, or ``""``."""
    for child in information:
        if _local_name(child.tag) == name:
            return "".join((child.text or "").split())
    return ""


def _local_name(tag: str) -> str:
    """Return an XML tag without its ``{namespace}`` prefix."""
    return tag.rsplit("}", 1)[-1]
