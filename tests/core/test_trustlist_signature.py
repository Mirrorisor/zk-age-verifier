"""An ETSI trusted list's XML signature and NextUpdate (#91).

The list's signature must verify against one of the certificates the operator names as
authorised to sign it (``etsi_xml_signers``), and a list past its ``NextUpdate`` is refused.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from lxml import etree
from signxml.algorithms import DigestAlgorithm, SignatureConstructionMethod, SignatureMethod
from signxml.signer import XMLSigner
from structlog.testing import capture_logs

from tests.core.test_trustlist import (
    AV_TL_ACCEPTANCE_LIST_SIGNER,
    AV_TL_ACCEPTANCE_RECOGNIZED_COUNT,
    AV_TL_ACCEPTANCE_XML,
    AV_TL_PRODUCTION_RECOGNIZED,
    AV_TL_PRODUCTION_XML,
    _cert,
    _ClockAt,
    _etsi_xml,
    _self_signed,
)
from zk_age_verifier.config import ConfigError, TrustSource
from zk_age_verifier.core import trustlist
from zk_age_verifier.core.trustlist import load_anchors

DATA = Path(__file__).parents[1] / "data"
# The six certificates in the production list's PointersToOtherTSL (the EU/EEA LOTL
# signers), and the acceptance list's own signer, which is not among the acceptance
# list's seven pointer certificates.
AV_TL_PRODUCTION_SIGNERS = DATA / "av-tl-production-2026-11-15-signers.pem"
AV_TL_ACCEPTANCE_SIGNER = DATA / "av-tl-acceptance-2026-11-15-signer.pem"
AV_TL_PRODUCTION_LIST_SIGNER = "e0a620fbb6747362bb933ac44169d676a553444716cf5f31605f12a22b8396b1"
XMLDSIG = "http://www.w3.org/2000/09/xmldsig#"
PAST = "<dateTime>2000-01-01T00:00:00Z</dateTime>"
FUTURE = "<dateTime>2999-01-01T00:00:00Z</dateTime>"


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
            method=SignatureConstructionMethod.enveloped,
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


def _source(listing: Path, signers: Path) -> TrustSource:
    return TrustSource(etsi_xml=str(listing), etsi_xml_signers=str(signers))


def _fingerprints(source: TrustSource) -> set[str]:
    return {a.fingerprint(hashes.SHA256()).hex() for a in load_anchors([source]).anchors}


@pytest.mark.usefixtures("capture_day")
def test_production_list_verifies_against_its_pointer_signers() -> None:
    with capture_logs() as logs:
        loaded = _fingerprints(_source(AV_TL_PRODUCTION_XML, AV_TL_PRODUCTION_SIGNERS))
    assert loaded == set(AV_TL_PRODUCTION_RECOGNIZED)
    (event,) = [entry for entry in logs if entry["event"] == "etsi_xml_signature_verified"]
    assert event["signer_sha256"] == AV_TL_PRODUCTION_LIST_SIGNER


@pytest.mark.usefixtures("capture_day")
def test_acceptance_list_is_refused_with_the_production_signers() -> None:
    # Its signer, "TEST European Commission", is not one of the authorised set.
    with pytest.raises(ConfigError, match="failed its signature check"):
        load_anchors([_source(AV_TL_ACCEPTANCE_XML, AV_TL_PRODUCTION_SIGNERS)])


@pytest.mark.usefixtures("capture_day")
def test_acceptance_list_verifies_against_its_named_test_signer() -> None:
    with capture_logs() as logs:
        loaded = _fingerprints(_source(AV_TL_ACCEPTANCE_XML, AV_TL_ACCEPTANCE_SIGNER))
    assert len(loaded) == AV_TL_ACCEPTANCE_RECOGNIZED_COUNT
    (event,) = [entry for entry in logs if entry["event"] == "etsi_xml_signature_verified"]
    assert event["signer_sha256"] == AV_TL_ACCEPTANCE_LIST_SIGNER


@pytest.mark.usefixtures("capture_day")
def test_a_changed_real_list_is_refused(tmp_path: Path) -> None:
    data = AV_TL_PRODUCTION_XML.read_bytes()
    changed = data.replace(b"service-status/recognized", b"service-status/granted", 1)
    assert changed != data
    with pytest.raises(ConfigError, match="failed its signature check"):
        load_anchors([_source(_write(tmp_path, changed), AV_TL_PRODUCTION_SIGNERS)])


def test_production_list_is_refused_from_its_next_update(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(trustlist, "datetime", _ClockAt(datetime(2027, 4, 28, 13, tzinfo=UTC)))
    with pytest.raises(ConfigError, match="expired: its NextUpdate was 2027-04-28T13:00:00Z"):
        load_anchors([_source(AV_TL_PRODUCTION_XML, AV_TL_PRODUCTION_SIGNERS)])


def test_without_signers_the_list_loads_with_a_warning(tmp_path: Path) -> None:
    anchor = _self_signed()
    listing = _write(tmp_path, _etsi_xml(anchor, next_update=FUTURE))
    with capture_logs() as logs:
        anchors = load_anchors([TrustSource(etsi_xml=str(listing))])
    assert anchors.resolve(anchor)
    assert [entry for entry in logs if entry["event"] == "etsi_xml_signature_not_checked"]


def test_a_signed_list_loads_from_a_directory_of_signers(tmp_path: Path) -> None:
    anchor = _self_signed()
    signers = tmp_path / "signers"
    signers.mkdir()
    _Signer(signers, "other")
    named = _Signer(signers, "named")
    listing = _write(tmp_path, named.sign(_etsi_xml(anchor)))
    assert load_anchors([_source(listing, signers)]).resolve(anchor)


def test_a_tampered_list_is_refused(tmp_path: Path) -> None:
    signer = _Signer(tmp_path)
    data = signer.sign(_etsi_xml(_self_signed(), status="granted"))
    listing = _write(tmp_path, data.replace(b"granted", b"withdrawn"))
    with pytest.raises(ConfigError, match="failed its signature check"):
        load_anchors([_source(listing, signer.pem)])


def test_a_list_signed_by_someone_else_is_refused(tmp_path: Path) -> None:
    named = _Signer(tmp_path, "named")
    other = _Signer(tmp_path, "other")
    listing = _write(tmp_path, other.sign(_etsi_xml(_self_signed())))
    with pytest.raises(ConfigError, match="failed its signature check"):
        load_anchors([_source(listing, named.pem)])


def test_an_unsigned_list_is_refused_when_signers_are_named(tmp_path: Path) -> None:
    signer = _Signer(tmp_path)
    listing = _write(tmp_path, _etsi_xml(_self_signed()))
    with pytest.raises(ConfigError, match="failed its signature check"):
        load_anchors([_source(listing, signer.pem)])


def test_a_signature_without_signed_info_is_refused(tmp_path: Path) -> None:
    signer = _Signer(tmp_path)
    listing = _write(tmp_path, _etsi_xml(_self_signed(), signer=signer.cert))
    with pytest.raises(ConfigError, match="failed its signature check"):
        load_anchors([_source(listing, signer.pem)])


def test_malformed_xml_is_refused_when_signers_are_named(tmp_path: Path) -> None:
    signer = _Signer(tmp_path)
    listing = _write(tmp_path, b"<TrustServiceStatusList")
    with pytest.raises(ConfigError, match="failed its signature check"):
        load_anchors([_source(listing, signer.pem)])


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
        load_anchors([_source(listing, signer.pem)])


def test_two_signed_references_load_when_one_covers_the_whole_list(tmp_path: Path) -> None:
    anchor = _self_signed()
    signer = _Signer(tmp_path)
    # The services element is signed first and the whole list second, so the loader has to
    # pick the reference that covers the list rather than the first one it sees.
    listing = _write(tmp_path, signer.sign(_list_with_ids(anchor), ["#svc", "#tsl"]))
    assert load_anchors([_source(listing, signer.pem)]).resolve(anchor)


def test_a_signature_over_only_part_of_the_list_is_refused(tmp_path: Path) -> None:
    signer = _Signer(tmp_path)
    listing = _write(tmp_path, signer.sign(_list_with_ids(_self_signed()), "#svc"))
    with pytest.raises(ConfigError, match="no signed part covers the whole list"):
        load_anchors([_source(listing, signer.pem)])


@pytest.mark.parametrize("content", [None, b"not a certificate"])
def test_unreadable_signers_are_refused(tmp_path: Path, content: bytes | None) -> None:
    listing = _write(tmp_path, _etsi_xml(_self_signed()))
    pem = tmp_path / "signers.pem"
    if content is not None:
        pem.write_bytes(content)
    with pytest.raises(ConfigError, match="cannot read list signer certificates"):
        load_anchors([_source(listing, pem)])


def test_an_empty_signers_directory_is_refused(tmp_path: Path) -> None:
    listing = _write(tmp_path, _etsi_xml(_self_signed()))
    empty = tmp_path / "signers"
    empty.mkdir()
    with pytest.raises(ConfigError, match="hold no certificate"):
        load_anchors([_source(listing, empty)])


def test_a_list_past_its_next_update_is_refused(tmp_path: Path) -> None:
    listing = _write(tmp_path, _etsi_xml(_self_signed(), next_update=PAST))
    with pytest.raises(ConfigError, match="expired"):
        load_anchors([TrustSource(etsi_xml=str(listing))])


def test_a_signed_list_past_its_next_update_is_refused(tmp_path: Path) -> None:
    signer = _Signer(tmp_path)
    listing = _write(tmp_path, signer.sign(_etsi_xml(_self_signed(), next_update=PAST)))
    with pytest.raises(ConfigError, match="expired"):
        load_anchors([_source(listing, signer.pem)])


def test_a_next_update_without_a_zone_is_read_as_utc(tmp_path: Path) -> None:
    listing = _write(
        tmp_path, _etsi_xml(_self_signed(), next_update="<dateTime>2000-01-01T00:00:00</dateTime>")
    )
    with pytest.raises(ConfigError, match="expired"):
        load_anchors([TrustSource(etsi_xml=str(listing))])


def test_a_next_update_that_is_not_a_date_is_refused(tmp_path: Path) -> None:
    listing = _write(tmp_path, _etsi_xml(_self_signed(), next_update="<dateTime>soon</dateTime>"))
    with pytest.raises(ConfigError, match="not a date and time"):
        load_anchors([TrustSource(etsi_xml=str(listing))])


@pytest.mark.parametrize("next_update", [None, ""])
def test_a_list_without_a_next_update_loads_with_a_warning(
    tmp_path: Path, next_update: str | None
) -> None:
    anchor = _self_signed()
    listing = _write(tmp_path, _etsi_xml(anchor, next_update=next_update))
    with capture_logs() as logs:
        assert load_anchors([TrustSource(etsi_xml=str(listing))]).resolve(anchor)
    assert [entry for entry in logs if entry["event"] == "etsi_xml_no_next_update"]
