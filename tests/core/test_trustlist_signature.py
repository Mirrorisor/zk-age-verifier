"""An ETSI trusted list's XML signature is verified against one named signer certificate."""

import hashlib
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from lxml import etree
from signxml import DigestAlgorithm, SignatureMethod, XMLSigner, methods
from structlog.testing import capture_logs

from tests.core.test_trustlist import _cert, _etsi_xml, _self_signed
from zk_age_verifier.config import ConfigError, TrustSource
from zk_age_verifier.core.trustlist import load_anchors

XMLDSIG = "http://www.w3.org/2000/09/xmldsig#"


class _Signer:
    """A throwaway list signer: a key, its certificate, and the PEM file naming it."""

    def __init__(self, directory: Path, name: str = "list-signer") -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cert = _cert(self.key, name, name, self.key)
        self.pem = directory / f"{name}.pem"
        self.pem.write_bytes(self.cert.public_bytes(Encoding.PEM))

    def sign(self, xml: bytes, reference_uri: str | list[str] | None = None) -> bytes:
        """Return ``xml`` with an enveloped ECDSA signature from this signer."""
        signer = XMLSigner(
            method=methods.enveloped,
            signature_algorithm=SignatureMethod.ECDSA_SHA256,
            digest_algorithm=DigestAlgorithm.SHA256,
        )
        signed = signer.sign(
            etree.fromstring(xml),
            key=self.key,
            cert=self.cert.public_bytes(Encoding.PEM).decode("ascii"),
            reference_uri=reference_uri,
        )
        return bytes(etree.tostring(signed))


def _list_with_ids(anchor: x509.Certificate) -> bytes:
    """A trusted list whose root and services element carry ``Id`` attributes."""
    return (
        _etsi_xml(anchor)
        .replace(b"<TrustServiceStatusList ", b'<TrustServiceStatusList Id="tsl" ', 1)
        .replace(b"<TSPServices>", b'<TSPServices Id="svc">', 1)
    )


def _write(directory: Path, data: bytes) -> Path:
    listing = directory / "tsl.xml"
    listing.write_bytes(data)
    return listing


def test_a_signed_list_loads_and_logs_the_signer(tmp_path: Path) -> None:
    anchor = _self_signed()
    signer = _Signer(tmp_path)
    listing = _write(tmp_path, signer.sign(_etsi_xml(anchor)))
    with capture_logs() as logs:
        anchors = load_anchors(
            [TrustSource(etsi_xml=str(listing), etsi_xml_signer=str(signer.pem))]
        )
    assert anchors.resolve(anchor)
    (event,) = [entry for entry in logs if entry["event"] == "etsi_xml_signature_verified"]
    assert event["signer_sha256"] == signer.cert.fingerprint(hashes.SHA256()).hex()
    assert not [entry for entry in logs if entry["event"] == "etsi_xml_not_pinned"]


def test_a_signed_list_with_a_matching_pin_loads(tmp_path: Path) -> None:
    anchor = _self_signed()
    signer = _Signer(tmp_path)
    data = signer.sign(_etsi_xml(anchor))
    listing = _write(tmp_path, data)
    source = TrustSource(
        etsi_xml=str(listing),
        etsi_xml_sha256=hashlib.sha256(data).hexdigest(),
        etsi_xml_signer=str(signer.pem),
    )
    assert load_anchors([source]).resolve(anchor)


def test_a_tampered_list_is_refused(tmp_path: Path) -> None:
    signer = _Signer(tmp_path)
    data = signer.sign(_etsi_xml(_self_signed(), status="granted"))
    listing = _write(tmp_path, data.replace(b"granted", b"withdrawn"))
    with pytest.raises(ConfigError, match="failed its signature check"):
        load_anchors([TrustSource(etsi_xml=str(listing), etsi_xml_signer=str(signer.pem))])


def test_a_list_signed_by_someone_else_is_refused(tmp_path: Path) -> None:
    named = _Signer(tmp_path, "named")
    other = _Signer(tmp_path, "other")
    listing = _write(tmp_path, other.sign(_etsi_xml(_self_signed())))
    with pytest.raises(ConfigError, match="failed its signature check"):
        load_anchors([TrustSource(etsi_xml=str(listing), etsi_xml_signer=str(named.pem))])


def test_an_unsigned_list_is_refused_when_a_signer_is_named(tmp_path: Path) -> None:
    signer = _Signer(tmp_path)
    listing = _write(tmp_path, _etsi_xml(_self_signed()))
    with pytest.raises(ConfigError, match="failed its signature check"):
        load_anchors([TrustSource(etsi_xml=str(listing), etsi_xml_signer=str(signer.pem))])


def test_a_signature_without_signed_info_is_refused(tmp_path: Path) -> None:
    signer = _Signer(tmp_path)
    listing = _write(tmp_path, _etsi_xml(_self_signed(), signer=signer.cert))
    with pytest.raises(ConfigError, match="failed its signature check"):
        load_anchors([TrustSource(etsi_xml=str(listing), etsi_xml_signer=str(signer.pem))])


def test_malformed_xml_is_refused_when_a_signer_is_named(tmp_path: Path) -> None:
    signer = _Signer(tmp_path)
    listing = _write(tmp_path, b"<TrustServiceStatusList")
    with pytest.raises(ConfigError, match="failed its signature check"):
        load_anchors([TrustSource(etsi_xml=str(listing), etsi_xml_signer=str(signer.pem))])


def test_a_signature_with_too_many_references_is_refused(tmp_path: Path) -> None:
    signer = _Signer(tmp_path)
    references = f'<ds:Reference xmlns:ds="{XMLDSIG}"/>' * 6
    xml = (
        '<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">'
        f'<ds:Signature xmlns:ds="{XMLDSIG}"><ds:SignedInfo>{references}</ds:SignedInfo>'
        "</ds:Signature></TrustServiceStatusList>"
    )
    listing = _write(tmp_path, xml.encode("ascii"))
    with pytest.raises(ConfigError, match="6 references"):
        load_anchors([TrustSource(etsi_xml=str(listing), etsi_xml_signer=str(signer.pem))])


@pytest.mark.parametrize("content", [None, b"not a certificate"])
def test_an_unreadable_signer_certificate_is_refused(tmp_path: Path, content: bytes | None) -> None:
    listing = _write(tmp_path, _etsi_xml(_self_signed()))
    pem = tmp_path / "missing.pem"
    if content is not None:
        pem.write_bytes(content)
    with pytest.raises(ConfigError, match="cannot read list signer certificate"):
        load_anchors([TrustSource(etsi_xml=str(listing), etsi_xml_signer=str(pem))])


def test_two_signed_references_load_when_one_covers_the_whole_list(tmp_path: Path) -> None:
    anchor = _self_signed()
    signer = _Signer(tmp_path)
    # The services element is signed first and the whole list second, so the loader has to
    # pick the reference that covers the list rather than the first one it sees.
    listing = _write(tmp_path, signer.sign(_list_with_ids(anchor), ["#svc", "#tsl"]))
    anchors = load_anchors([TrustSource(etsi_xml=str(listing), etsi_xml_signer=str(signer.pem))])
    assert anchors.resolve(anchor)


def test_a_signature_over_only_part_of_the_list_is_refused(tmp_path: Path) -> None:
    signer = _Signer(tmp_path)
    listing = _write(tmp_path, signer.sign(_list_with_ids(_self_signed()), "#svc"))
    with pytest.raises(ConfigError, match="no signed part covers the whole list"):
        load_anchors([TrustSource(etsi_xml=str(listing), etsi_xml_signer=str(signer.pem))])
