"""The response-verification pipeline: decrypt, parse, and check a ZK proof.

The DC transport opens the crypto envelope and reconstructs the transcript, then
the mdoc ZK engine parses and verifies the presentation. Every failure from
either step maps to one terminal machine reason. The result is a
``VerdictVerified`` listing the checked claims or a ``VerdictFailed`` naming the
reason. Each outcome logs one event with the public id, timing, and reason;
never proof contents, key material, or issuer identity.
"""

import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Literal

import structlog
from pydantic import BaseModel, Field
from pylongfellow import mdoc

from zk_age_verifier.config import Config
from zk_age_verifier.core.engine.circuits import HeldCircuit
from zk_age_verifier.core.engine.mdoc_zk import (
    ClaimMismatch,
    EngineResult,
    MalformedPresentation,
    StaleProof,
    StandardMdocNotAccepted,
    UnsupportedCircuit,
    verify_presentation,
)
from zk_age_verifier.core.transport.dc import (
    DecryptFailed,
    InvalidEnvelope,
    build_session_transcript,
    open_response,
    parse_response_wrapper,
)
from zk_age_verifier.core.trustlist import AnchorSet, UntrustedIssuer
from zk_age_verifier.service.sessions import Session

log = structlog.get_logger(__name__)

FailureReason = Literal[
    "invalid-envelope",
    "decrypt-failed",
    "standard-mdoc-not-accepted",
    "unsupported-circuit",
    "claim-mismatch",
    "stale-proof",
    "untrusted-issuer",
    "proof-invalid",
    "engine-error",
]
"""The machine reason set for a failed verdict."""


class VerdictVerified(BaseModel):
    """The presentation 200 body when the proof verifies."""

    state: Literal["verified"]
    result: dict[str, bool] = Field(
        description="One entry per requested check; every value is true in a verified verdict."
    )
    verified_at: str = Field(description="ISO 8601 UTC time of verification.")


class VerdictFailed(BaseModel):
    """The presentation 200 body when verification fails at any step."""

    state: Literal["failed"]
    reason: FailureReason = Field(description="The step that failed, as a machine string.")


Verdict = Annotated[VerdictVerified | VerdictFailed, Field(discriminator="state")]
"""The presentation verdict, verified or failed, discriminated on ``state``."""


@dataclass(frozen=True)
class PresentationContext:
    """The transport phase's output, consumed by the engine call.

    Attributes:
        plaintext: The decrypted DeviceResponse bytes.
        transcript: The reconstructed session transcript the proof is bound to.
        claims: The session's requested checks.
    """

    plaintext: bytes
    transcript: bytes
    claims: tuple[str, ...]


class _Failed(Exception):
    """Carries the terminal machine reason and an optional log detail."""

    def __init__(self, reason: FailureReason, detail: str | None = None) -> None:
        """Record the terminal machine reason and an optional log detail."""
        self.reason = reason
        self.detail = detail


async def verify_response(
    session: Session,
    held: HeldCircuit,
    anchors: AnchorSet,
    body: dict[str, object],
    config: Config,
) -> Verdict:
    """Verify a relayed wallet response and return the terminal verdict.

    Args:
        session: The claimed session, already taken for its one attempt.
        held: The circuit this verifier holds and advertises.
        anchors: The resolved trust anchors.
        body: The DigitalCredential ``data`` object, ``{"response": ...}``.
        config: The service configuration (clock-skew tolerance).

    Returns:
        A ``VerdictVerified`` on success, or a ``VerdictFailed`` naming the reason.
    """
    started = time.perf_counter()
    try:
        verdict = await _run(session, held, anchors, body, config)
    except _Failed as failure:
        log.info(
            "verify_failed",
            session_id=session.session_id,
            reason=failure.reason,
            detail=failure.detail,
            elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
        )
        return VerdictFailed(state="failed", reason=failure.reason)
    log.info(
        "verify_succeeded",
        session_id=session.session_id,
        elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
    )
    return verdict


async def _run(
    session: Session,
    held: HeldCircuit,
    anchors: AnchorSet,
    body: dict[str, object],
    config: Config,
) -> VerdictVerified:
    """Run the pipeline, raising ``_Failed`` at the first terminal failure."""
    context = _open_presentation(session, body)
    result = await _run_engine(context, held, anchors, config)
    return VerdictVerified(
        state="verified",
        result={claim: True for claim in result.claims},
        verified_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    )


def _open_presentation(session: Session, body: dict[str, object]) -> PresentationContext:
    """Run the transport phase: unwrap, reconstruct the transcript, HPKE open."""
    try:
        enc, ciphertext = parse_response_wrapper(body)
    except InvalidEnvelope as exc:
        raise _Failed("invalid-envelope") from exc

    transcript = build_session_transcript(session.dc.encryption_info_b64, session.expected_origin)
    try:
        plaintext = open_response(enc, ciphertext, session.dc.private_key, transcript)
    except DecryptFailed as exc:
        raise _Failed("decrypt-failed") from exc

    return PresentationContext(plaintext=plaintext, transcript=transcript, claims=session.claims)


async def _run_engine(
    context: PresentationContext, held: HeldCircuit, anchors: AnchorSet, config: Config
) -> EngineResult:
    """Run the engine, mapping every engine failure to a terminal machine reason."""
    try:
        return await verify_presentation(
            context.plaintext,
            context.transcript,
            held,
            anchors,
            context.claims,
            config.service.timestamp_skew_seconds,
            profiles=config.service.profiles,
        )
    except MalformedPresentation as exc:
        raise _Failed("invalid-envelope") from exc
    except StandardMdocNotAccepted as exc:
        raise _Failed("standard-mdoc-not-accepted") from exc
    except UnsupportedCircuit as exc:
        raise _Failed("unsupported-circuit", exc.detail) from exc
    except ClaimMismatch as exc:
        raise _Failed("claim-mismatch") from exc
    except StaleProof as exc:
        raise _Failed("stale-proof") from exc
    except UntrustedIssuer as exc:
        raise _Failed("untrusted-issuer") from exc
    except mdoc.VerifierError as exc:
        raise _Failed("proof-invalid", exc.code.name if exc.code is not None else None) from exc
    except Exception as exc:
        log.exception("verify_engine_error")
        raise _Failed("engine-error") from exc
