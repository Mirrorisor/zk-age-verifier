"""Protocol constants pinned by the credential profiles, shared across transport and engine."""

from dataclasses import dataclass


@dataclass(frozen=True)
class CredentialProfile:
    """One kind of credential the service can be configured to accept.

    The doctype names the credential; the namespace is where its claims live. For the
    EU age-verification credential the two are the same string. For an ISO mobile
    driving licence they differ.

    Attributes:
        name: The value of ``[service] credential`` that selects this profile.
        doc_type: The credential doctype the proof is scoped to.
        namespace: The claim namespace holding the requested elements.
    """

    name: str
    doc_type: str
    namespace: str


EU_AV = CredentialProfile(name="eu-av", doc_type="eu.europa.ec.av.1", namespace="eu.europa.ec.av.1")
"""The EU age-verification credential. The default."""

ISO_MDL = CredentialProfile(
    name="iso-mdl", doc_type="org.iso.18013.5.1.mDL", namespace="org.iso.18013.5.1"
)
"""An ISO/IEC 18013-5 mobile driving licence, asked for ``age_over_NN`` elements."""

PROFILES: dict[str, CredentialProfile] = {EU_AV.name: EU_AV, ISO_MDL.name: ISO_MDL}
"""Every selectable profile, by name."""

DOC_TYPE = EU_AV.doc_type
"""The AV credential doctype and claim namespace (the default profile's)."""
