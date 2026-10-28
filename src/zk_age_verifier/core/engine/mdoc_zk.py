"""The mdoc ZK engine: parse a DeviceResponse and verify its Longfellow proof.

This engine consumes decrypted presentation bytes, the session transcript, the
held circuit, the trust anchors, and the requested claims; it returns the
verified claims. It never touches transport framing or the crypto envelope, and
it does not import the transport.
"""

import asyncio
import functools
from dataclasses import dataclass
from datetime import UTC, datetime

import cbor2
import structlog
from cryptography import x509
from pylongfellow import mdoc

from zk_age_verifier.core.constants import CredentialProfile
from zk_age_verifier.core.engine.circuits import HeldCircuit
from zk_age_verifier.core.trustlist import AnchorSet

log = structlog.get_logger(__name__)

# CBOR true, the disclosed value every age check requires.
_CLAIM_TRUE = cbor2.dumps(True)

# CBOR empty map: the DeviceNameSpaces value assumed when the wire carries
# none (https://github.com/pipe23-org/pylongfellow/issues/29).
_ASSUMED_DEVICE_NAMESPACES = b"\xa0"


class MalformedPresentation(Exception):
    """Raised when the DeviceResponse or its ZkDocument is malformed."""


class StandardMdocNotAccepted(Exception):
    """Raised when the wallet returns a standard ``documents`` presentation."""


class UnsupportedCircuit(Exception):
    """Raised when the wallet proved with a circuit this verifier does not hold."""

    def __init__(self, detail: str) -> None:
        """Record the wallet-versus-holder circuit identities for the log line."""
        self.detail = detail
        super().__init__(detail)


class ClaimMismatch(Exception):
    """Raised when the docType or the disclosed claims do not match the request."""


class StaleProof(Exception):
    """Raised when the proof timestamp is outside the allowed clock skew."""


@dataclass(frozen=True)
class ZkDocument:
    """The first ZkDocument's proof and its public statement.

    Attributes:
        proof: The Longfellow ZK proof bytes.
        zk_system_id: The circuit-identity string the wallet used.
        doc_type: The credential doctype the proof is scoped to.
        timestamp: Proof-generation time (tag-0, timezone-aware).
        issuer_signed: The disclosed claims, namespace to element listing.
        device_signed: Expected empty; a claim listing if a wallet populates it.
        mso_x5chain: The issuer DS certificate.
        device_name_spaces_bytes: Inner bytes of the tag-24 DeviceNameSpacesBytes
            the proof is bound to; always ``None`` from the parser, since the
            response format has no field that carries it.
    """

    proof: bytes
    zk_system_id: str
    doc_type: str
    timestamp: datetime
    issuer_signed: dict[str, object]
    device_signed: object
    mso_x5chain: x509.Certificate
    device_name_spaces_bytes: bytes | None


@dataclass(frozen=True)
class EngineResult:
    """The engine's verdict for a verified presentation.

    Attributes:
        claims: The claims the proof established, every value true.
    """

    claims: tuple[str, ...]


async def verify_presentation(
    presentation: bytes,
    transcript: bytes,
    held: HeldCircuit,
    anchors: AnchorSet,
    claims: tuple[str, ...],
    timestamp_skew_seconds: int,
    *,
    profile: CredentialProfile,
) -> EngineResult:
    """Verify a decrypted presentation and return the established claims.

    The backend's verify call is synchronous, so the proof check runs in a
    thread-pool executor. Every step before it stays on the event loop.

    Args:
        presentation: The HPKE-opened DeviceResponse CBOR.
        transcript: The session transcript the proof is bound to.
        held: The circuit this verifier holds and advertises.
        anchors: The resolved trust anchors.
        claims: The session's requested checks.
        timestamp_skew_seconds: The allowed skew on the proof timestamp.
        profile: The credential profile the service accepts; its doctype and claim
            namespace are what the response must carry and what the proof is bound to.

    Returns:
        The established claims.

    Raises:
        MalformedPresentation: The DeviceResponse is malformed.
        StandardMdocNotAccepted: The response is a standard ``documents`` presentation.
        UnsupportedCircuit: The wallet used a circuit this verifier does not hold.
        ClaimMismatch: The docType or disclosed claims do not match the request.
        StaleProof: The proof timestamp is outside the allowed skew.
        UntrustedIssuer: No anchor accepts the issuer certificate.
        mdoc.VerifierError: The proof failed to verify.
    """
    document = parse_device_response(presentation)

    if document.zk_system_id != held.zk_system_id:
        raise UnsupportedCircuit(
            f"wallet used {document.zk_system_id}, holder has {held.zk_system_id}"
        )

    if document.doc_type != profile.doc_type or not _claims_disclosed(
        document.issuer_signed, profile.namespace, claims
    ):
        raise ClaimMismatch("docType or disclosed claims do not match the request")

    now = datetime.now(UTC)
    if abs((now - document.timestamp).total_seconds()) > timestamp_skew_seconds:
        raise StaleProof("proof timestamp is outside the allowed skew")

    issuer_public_key = mdoc.PublicKey(*anchors.resolve(document.mso_x5chain))

    # Where the wire carries no DeviceNameSpacesBytes, the service substitutes
    # the empty map — a stated assumption about deployed devices
    # (https://github.com/pipe23-org/pylongfellow/issues/29).
    device_namespaces = document.device_name_spaces_bytes
    if device_namespaces is None:
        device_namespaces = _ASSUMED_DEVICE_NAMESPACES

    requested = [mdoc.RequestedAttribute(profile.namespace, claim, _CLAIM_TRUE) for claim in claims]
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(
        None,
        functools.partial(
            held.longfellow.verify,
            issuer_public_key,
            transcript,
            requested,
            document.timestamp,
            document.proof,
            profile.doc_type,
            device_namespaces=device_namespaces,
        ),
    )

    return EngineResult(claims=claims)


def parse_device_response(plaintext: bytes) -> ZkDocument:
    """Parse the decrypted DeviceResponse and return its first ZkDocument.

    Args:
        plaintext: The HPKE-opened DeviceResponse CBOR.

    Returns:
        The first ZkDocument.

    Raises:
        StandardMdocNotAccepted: The response carries ``documents``, not
            ``zkDocuments`` — a standard, correlatable presentation.
        MalformedPresentation: The response is otherwise malformed.
    """
    try:
        response = cbor2.loads(plaintext)
    except Exception as exc:
        raise MalformedPresentation("plaintext is not valid CBOR") from exc
    if not isinstance(response, dict):
        raise MalformedPresentation("DeviceResponse is not a map")
    zk_documents = response.get("zkDocuments")
    if zk_documents is None:
        if "documents" in response:
            raise StandardMdocNotAccepted("standard mdoc documents are not accepted")
        raise MalformedPresentation("DeviceResponse has no zkDocuments")
    if not (isinstance(zk_documents, list) and zk_documents):
        raise MalformedPresentation("zkDocuments is empty or not a list")
    return _parse_zk_document(zk_documents[0])


def _parse_zk_document(zk_doc: object) -> ZkDocument:
    """Parse one ZkDocument map into a :class:`ZkDocument`."""
    if not isinstance(zk_doc, dict):
        raise MalformedPresentation("zkDocument is not a map")
    try:
        proof = zk_doc["proof"]
        raw_document_data = zk_doc["documentData"]
        if not isinstance(raw_document_data, cbor2.CBORTag) or raw_document_data.tag != 24:
            raise MalformedPresentation("documentData is not tag-24 encoded CBOR")
        try:
            document_data = cbor2.loads(raw_document_data.value)
        except Exception as exc:
            raise MalformedPresentation("documentData is not valid CBOR") from exc
        zk_system_id = document_data["zkSystemId"]
        doc_type = document_data["docType"]
        timestamp = document_data["timestamp"]
        issuer_signed = document_data["issuerSigned"]
        device_signed = document_data["deviceSigned"]
        raw_chain = document_data["msoX5chain"]
        leaf = raw_chain[0] if isinstance(raw_chain, list) else raw_chain
        mso_x5chain = x509.load_der_x509_certificate(leaf)
    except (KeyError, AttributeError, TypeError, ValueError, IndexError) as exc:
        raise MalformedPresentation("zkDocument is missing or malformed") from exc
    if not (
        isinstance(proof, bytes)
        and isinstance(zk_system_id, str)
        and isinstance(doc_type, str)
        and isinstance(timestamp, datetime)
        and timestamp.tzinfo is not None
        and isinstance(issuer_signed, dict)
    ):
        raise MalformedPresentation("zkDocument fields have the wrong types")
    if device_signed:
        log.warning("zk_document_device_signed_populated")
    return ZkDocument(
        proof=proof,
        zk_system_id=zk_system_id,
        doc_type=doc_type,
        timestamp=timestamp,
        issuer_signed=issuer_signed,
        device_signed=device_signed,
        mso_x5chain=mso_x5chain,
        # The response format has no field to read this from.
        device_name_spaces_bytes=None,
    )


def _claims_disclosed(
    issuer_signed: dict[str, object], namespace: str, claims: tuple[str, ...]
) -> bool:
    """Report whether every requested claim is disclosed as true in the namespace."""
    disclosed = issuer_signed.get(namespace)
    if not isinstance(disclosed, list):
        return False
    present = {
        entry.get("elementIdentifier")
        for entry in disclosed
        if isinstance(entry, dict) and entry.get("elementValue") is True
    }
    return all(claim in present for claim in claims)
