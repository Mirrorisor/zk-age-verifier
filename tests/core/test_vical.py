"""A VICAL (ISO/IEC 18013-5 Annex C issuer list) is verified before its issuers are trusted."""

from datetime import timedelta
from pathlib import Path
from typing import Any

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from structlog.testing import capture_logs

from tests.core.test_trustlist import NOW, _cert, _self_signed
from zk_age_verifier.config import ConfigError, TrustSource
from zk_age_verifier.core.trustlist import load_anchors
from zk_age_verifier.core.vical import describe_vical, load_vical

MDL = "org.iso.18013.5.1.mDL"
VICAL_SIGNER_EKU = x509.ObjectIdentifier("1.0.18013.5.1.8")
EU_AV = "eu.europa.ec.av.1"
# A byte string that promises five bytes and has two: not valid CBOR.
TRUNCATED = b"\x45ab"


class _Provider:
    """A throwaway VICAL provider: a CA, a signer it issued, and a way to sign lists."""

    def __init__(self, curve: ec.EllipticCurve | None = None) -> None:
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.ca = _cert(self.ca_key, "vical-ca", "vical-ca", self.ca_key, ca=True)
        self.key = ec.generate_private_key(curve or ec.SECP256R1())
        self.signer = _signer_cert(self.key, self.ca_key)

    def sign(
        self,
        content: dict[str, Any] | bytes,
        *,
        alg: int = -7,
        digest: hashes.HashAlgorithm | None = None,
        tagged: bool = True,
        x5chain: object = "der",
        in_protected: bool = False,
        signed_payload: bytes | None = None,
    ) -> bytes:
        """Return ``content`` as a COSE_Sign1 message signed by this provider's signer.

        ``signed_payload`` signs other bytes than the ones sent, for a broken signature.
        """
        payload = content if isinstance(content, bytes) else cbor2.dumps(content)
        der = self.signer.public_bytes(Encoding.DER)
        chain: object = x5chain
        if x5chain == "der":
            chain = der
        elif x5chain == "list":
            chain = [der]
        header: dict[int, object] = {1: alg}
        unprotected: dict[int, object] = {}
        if chain is not None:
            (header if in_protected else unprotected)[33] = chain
        protected = cbor2.dumps(header)
        to_be_signed = cbor2.dumps(["Signature1", protected, b"", signed_payload or payload])
        r, s = decode_dss_signature(
            self.key.sign(to_be_signed, ec.ECDSA(digest or hashes.SHA256()))
        )
        size = (self.key.curve.key_size + 7) // 8
        message = [protected, unprotected, payload, r.to_bytes(size) + s.to_bytes(size)]
        return cbor2.dumps(cbor2.CBORTag(18, message) if tagged else message)


def _signer_cert(
    key: ec.EllipticCurvePrivateKey,
    ca_key: ec.EllipticCurvePrivateKey,
    usages: list[x509.ObjectIdentifier] | None = None,
) -> x509.Certificate:
    """A VICAL signer issued by ``ca_key``, with the VICAL signer EKU unless ``usages`` says."""
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vical-signer")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vical-ca")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=365))
    )
    chosen = [VICAL_SIGNER_EKU] if usages is None else usages
    if chosen:
        builder = builder.add_extension(x509.ExtendedKeyUsage(chosen), critical=True)
    return builder.sign(ca_key, hashes.SHA256())


def _entry(
    cert: x509.Certificate, doc_types: object = (MDL,), country: object = "AU"
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "certificate": cert.public_bytes(Encoding.DER),
        "serialNumber": cert.serial_number,
        "ski": b"\x01" * 20,
        "issuingAuthority": "Test road authority",
    }
    if doc_types is not None:
        entry["docType"] = list(doc_types) if isinstance(doc_types, tuple) else doc_types
    if country is not None:
        entry["issuingCountry"] = country
    return entry


def _content(entries: list[Any], **fields: object) -> dict[str, Any]:
    content: dict[str, Any] = {
        "version": "1.0",
        "vicalProvider": "Test provider",
        "date": NOW - timedelta(days=1),
        "vicalIssueID": 7,
        "nextUpdate": NOW + timedelta(days=30),
        "certificateInfos": entries,
    }
    content.update(fields)
    return {key: value for key, value in content.items() if value is not None}


def _load(
    data: bytes, trusted: x509.Certificate, countries: list[str] | None = None
) -> list[x509.Certificate]:
    return load_vical(data, trusted, [MDL], countries, "test-vical")


def test_a_signed_vical_loads_the_issuers_for_the_chosen_doc_type() -> None:
    provider = _Provider()
    licence_root, age_root = _self_signed("licence-root"), _self_signed("age-root")
    data = provider.sign(_content([_entry(licence_root), _entry(age_root, doc_types=(EU_AV,))]))
    with capture_logs() as logs:
        anchors = _load(data, provider.ca)
    assert anchors == [licence_root]
    (event,) = [entry for entry in logs if entry["event"] == "vical_loaded"]
    assert event["provider"] == "Test provider"
    assert event["issue"] == 7
    assert event["anchors"] == 1
    assert event["signer_sha256"] == provider.signer.fingerprint(hashes.SHA256()).hex()


@pytest.mark.parametrize(
    ("tagged", "x5chain", "in_protected"),
    [(False, "der", False), (True, "list", False), (True, "der", True)],
)
def test_message_shapes_iso_allows_are_accepted(
    tagged: bool, x5chain: str, in_protected: bool
) -> None:
    provider = _Provider()
    root = _self_signed()
    data = provider.sign(
        _content([_entry(root)]), tagged=tagged, x5chain=x5chain, in_protected=in_protected
    )
    assert _load(data, provider.ca) == [root]


def test_the_signer_certificate_itself_can_be_the_configured_one() -> None:
    provider = _Provider()
    root = _self_signed()
    assert _load(provider.sign(_content([_entry(root)])), provider.signer) == [root]


def test_es384_with_a_p384_signer_is_accepted() -> None:
    provider = _Provider(ec.SECP384R1())
    root = _self_signed()
    data = provider.sign(_content([_entry(root)]), alg=-35, digest=hashes.SHA384())
    assert _load(data, provider.ca) == [root]


def test_a_vical_from_another_provider_is_refused() -> None:
    provider, other = _Provider(), _Provider()
    data = provider.sign(_content([_entry(_self_signed())]))
    with pytest.raises(ConfigError, match="neither the configured vical_signer nor issued by it"):
        _load(data, other.ca)


def test_a_broken_signature_is_refused() -> None:
    provider = _Provider()
    data = provider.sign(_content([_entry(_self_signed())]), signed_payload=b"something else")
    with pytest.raises(ConfigError, match="failed its signature check"):
        _load(data, provider.ca)


def test_a_signature_of_the_wrong_length_is_refused() -> None:
    provider = _Provider()
    message = cbor2.loads(provider.sign(_content([_entry(_self_signed())]), tagged=False))
    message[3] = message[3][:-1]
    with pytest.raises(ConfigError, match="wrong length"):
        _load(cbor2.dumps(message), provider.ca)


def test_an_expired_signer_certificate_is_refused() -> None:
    provider = _Provider()
    provider.signer = _cert(
        provider.key, "vical-signer", "vical-ca", provider.ca_key, not_after=NOW - timedelta(days=1)
    )
    with pytest.raises(ConfigError, match="not valid today"):
        _load(provider.sign(_content([_entry(_self_signed())])), provider.ca)


def test_a_signer_without_an_elliptic_curve_key_is_refused() -> None:
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rsa-signer")])
    rsa_signer = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(rsa_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=30))
        .sign(rsa_key, hashes.SHA256())
    )
    provider = _Provider()
    provider.signer = rsa_signer
    with pytest.raises(ConfigError, match="not an elliptic-curve key"):
        _load(provider.sign(_content([_entry(_self_signed())])), rsa_signer)


@pytest.mark.parametrize("alg", [None, -8, -257])
def test_algorithms_other_than_ecdsa_are_refused(alg: int | None) -> None:
    provider = _Provider()
    data = provider.sign(_content([_entry(_self_signed())]), alg=alg)  # type: ignore[arg-type]
    with pytest.raises(ConfigError, match="ES256, ES384 or ES512"):
        _load(data, provider.ca)


def test_an_empty_protected_header_names_no_algorithm() -> None:
    provider = _Provider()
    message = cbor2.loads(provider.sign(_content([_entry(_self_signed())]), tagged=False))
    message[0] = b""
    with pytest.raises(ConfigError, match="ES256, ES384 or ES512"):
        _load(cbor2.dumps(message), provider.ca)


@pytest.mark.parametrize("x5chain", [None, [], 5])
def test_a_vical_without_a_signer_certificate_is_refused(x5chain: object) -> None:
    provider = _Provider()
    data = provider.sign(_content([_entry(_self_signed())]), x5chain=x5chain)
    with pytest.raises(ConfigError, match="no signer certificate"):
        _load(data, provider.ca)


def test_an_unreadable_signer_certificate_is_refused() -> None:
    provider = _Provider()
    data = provider.sign(_content([_entry(_self_signed())]), x5chain=b"not a certificate")
    with pytest.raises(ConfigError, match="signer certificate is unreadable"):
        _load(data, provider.ca)


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (TRUNCATED, "is not CBOR"),
        (cbor2.dumps(cbor2.CBORTag(17, [b"", {}, b"", b""])), "tag 17"),
        (cbor2.dumps([b"", {}, None, b""]), "not a COSE_Sign1 message"),
        (cbor2.dumps({"not": "a list"}), "not a COSE_Sign1 message"),
        (cbor2.dumps([TRUNCATED, {}, b"", b""]), "protected header is not CBOR"),
    ],
)
def test_files_that_are_not_cose_sign1_are_refused(data: bytes, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        _load(data, _Provider().ca)


@pytest.mark.parametrize("payload", [cbor2.dumps(["a", "list"]), TRUNCATED])
def test_content_that_is_not_a_map_is_refused(payload: bytes) -> None:
    provider = _Provider()
    with pytest.raises(ConfigError, match="content is not"):
        _load(provider.sign(payload), provider.ca)


@pytest.mark.parametrize("field", ["nextUpdate", "notAfter"])
def test_a_vical_past_its_next_update_or_not_after_is_refused(field: str) -> None:
    provider = _Provider()
    content = _content([_entry(_self_signed())], **{field: NOW - timedelta(seconds=1)})
    with pytest.raises(ConfigError, match=f"expired: its {field}"):
        _load(provider.sign(content), provider.ca)


@pytest.mark.parametrize(
    "next_update",
    [
        None,
        (NOW + timedelta(days=1)).isoformat(),
        (NOW + timedelta(days=1)).replace(tzinfo=None).isoformat(),
        NOW + timedelta(days=1),
    ],
)
def test_dates_in_the_future_or_absent_load(next_update: object) -> None:
    provider = _Provider()
    root = _self_signed()
    content = _content([_entry(root)], nextUpdate=next_update, notAfter=NOW + timedelta(days=60))
    assert _load(provider.sign(content), provider.ca) == [root]


@pytest.mark.parametrize("next_update", ["soon", 1_900_000_000])
def test_a_date_that_is_not_a_date_is_refused(next_update: object) -> None:
    provider = _Provider()
    content = _content([_entry(_self_signed())], nextUpdate=next_update)
    with pytest.raises(ConfigError, match="nextUpdate that is not a date and time"):
        _load(provider.sign(content), provider.ca)


def test_a_vical_without_certificate_infos_is_refused() -> None:
    provider = _Provider()
    content = _content([])
    content["certificateInfos"] = "none"
    with pytest.raises(ConfigError, match="no certificateInfos list"):
        _load(provider.sign(content), provider.ca)


def test_entries_that_do_not_match_are_skipped() -> None:
    provider = _Provider()
    root = _self_signed("wanted")
    entries = [
        "not a map",
        _entry(_self_signed("no doc types"), doc_types=None),
        _entry(_self_signed("doc type text"), doc_types=MDL),
        _entry(_self_signed("other doc type"), doc_types=(EU_AV,)),
        _entry(root),
    ]
    assert _load(provider.sign(_content(entries)), provider.ca) == [root]


def test_countries_narrow_the_issuers() -> None:
    provider = _Provider()
    australian = _self_signed("au")
    entries = [
        _entry(australian, country="au"),
        _entry(_self_signed("us"), country="US"),
        _entry(_self_signed("no country"), country=None),
    ]
    assert _load(provider.sign(_content(entries)), provider.ca, countries=["AU"]) == [australian]


def test_an_unreadable_issuer_certificate_is_skipped_with_a_warning() -> None:
    provider = _Provider()
    root = _self_signed()
    broken = _entry(root)
    broken["certificate"] = b"broken"
    with capture_logs() as logs:
        anchors = _load(provider.sign(_content([broken, _entry(root)])), provider.ca)
    assert anchors == [root]
    (event,) = [entry for entry in logs if entry["event"] == "vical_bad_certificate"]
    assert event["issuing_authority"] == "Test road authority"


def test_a_vical_with_no_matching_issuer_is_refused() -> None:
    provider = _Provider()
    data = provider.sign(_content([_entry(_self_signed(), doc_types=(EU_AV,))]))
    with pytest.raises(ConfigError, match=r"lists no issuer for doc types \['org.iso"):
        _load(data, provider.ca)
    data = provider.sign(_content([_entry(_self_signed(), country="US")]))
    with pytest.raises(ConfigError, match=r"in \['AU'\]"):
        _load(data, provider.ca, countries=["au"])


def test_a_vical_trust_source_loads_through_load_anchors(tmp_path: Path) -> None:
    provider = _Provider()
    root = _self_signed()
    listing = tmp_path / "vical.cbor"
    listing.write_bytes(provider.sign(_content([_entry(root)])))
    signer_pem = tmp_path / "vical-ca.pem"
    signer_pem.write_bytes(provider.ca.public_bytes(Encoding.PEM))
    source = TrustSource(
        vical=str(listing),
        vical_signer=str(signer_pem),
        vical_doc_types=[MDL],
        vical_countries=["AU"],
    )
    anchors = load_anchors([source])
    assert anchors.anchors == (root,)


def test_an_algorithm_for_another_curve_is_refused() -> None:
    provider = _Provider(ec.SECP384R1())
    data = provider.sign(_content([_entry(_self_signed())]), alg=-7, digest=hashes.SHA256())
    with pytest.raises(ConfigError, match="algorithm for secp256r1, but the signer key is on"):
        _load(data, provider.ca)


def test_a_vical_without_a_next_update_loads_with_a_warning() -> None:
    provider = _Provider()
    root = _self_signed()
    with capture_logs() as logs:
        anchors = _load(provider.sign(_content([_entry(root)], nextUpdate=None)), provider.ca)
    assert anchors == [root]
    assert [entry for entry in logs if entry["event"] == "vical_no_next_update"]


def test_a_listed_issuer_outside_its_validity_is_skipped_with_a_warning() -> None:
    provider = _Provider()
    current, expired = _self_signed("current"), _self_signed("expired", NOW - timedelta(hours=1))
    with capture_logs() as logs:
        anchors = _load(provider.sign(_content([_entry(expired), _entry(current)])), provider.ca)
    assert anchors == [current]
    (event,) = [entry for entry in logs if entry["event"] == "vical_certificate_not_valid_now"]
    assert event["issuing_authority"] == "Test road authority"


@pytest.mark.parametrize("usages", [[], [x509.ObjectIdentifier("1.0.18013.5.1.2")]])
def test_a_signer_from_the_root_without_the_vical_signer_eku_is_refused(
    usages: list[x509.ObjectIdentifier],
) -> None:
    # No EKU at all, or the document signer EKU: another certificate from the same root.
    provider = _Provider()
    provider.signer = _signer_cert(provider.key, provider.ca_key, usages)
    with pytest.raises(ConfigError, match=r"not marked as a VICAL signer \(extended key usage"):
        _load(provider.sign(_content([_entry(_self_signed())])), provider.ca)


def test_a_signer_configured_directly_needs_no_eku() -> None:
    provider = _Provider()
    provider.signer = _signer_cert(provider.key, provider.ca_key, [])
    root = _self_signed()
    assert _load(provider.sign(_content([_entry(root)])), provider.signer) == [root]


def _describe(data: bytes, trusted: x509.Certificate) -> tuple[bool, str]:
    trusted_now, lines = describe_vical(data, trusted, "test-vical")
    return trusted_now, "\n".join(lines)


def test_describe_lists_every_issuer_of_a_good_vical() -> None:
    provider = _Provider()
    licence, age = _self_signed("licence-root"), _self_signed("age-root")
    expired = _self_signed("expired-root", NOW - timedelta(hours=1))
    entries: list[Any] = [_entry(licence), _entry(age, doc_types=(EU_AV,), country=None)]
    entries.append(_entry(expired))
    entries.append({"certificate": b"not der", "docType": [MDL]})
    entries.append(_entry(_self_signed("untyped-root"), doc_types=None))
    entries.append("not a map")
    ok, report = _describe(
        provider.sign(_content(entries, notAfter=NOW + timedelta(days=60))), provider.ca
    )
    assert ok
    assert report.endswith("\nTRUSTED")
    assert "[ok] signer is the configured certificate" in report
    assert "[ok] signature verifies" in report
    assert "provider: Test provider, issue 7" in report
    assert "[ok] nextUpdate" in report and "[ok] notAfter" in report
    assert "issuers: 6" in report
    assert "AU Test road authority: None; CN=untyped-root" in report
    assert f"AU Test road authority: {MDL}; CN=licence-root" in report
    assert f"?? Test road authority: {EU_AV}; CN=age-root" in report
    assert "CN=expired-root" in report and "(NOT VALID TODAY)" in report
    assert f"- ??: {MDL}; certificate unreadable" in report
    assert "- (not a map)" in report


def test_describe_shows_the_signer_and_fails_one_from_elsewhere() -> None:
    provider = _Provider()
    ok, report = _describe(provider.sign(_content([_entry(_self_signed())])), _Provider().ca)
    assert not ok
    assert "signer: CN=vical-signer" in report
    assert provider.signer.fingerprint(hashes.SHA256()).hex() in report
    assert "[FAIL]" in report and report.endswith("\nNOT TRUSTED")
    assert "provider:" not in report  # nothing from an unverified list is shown


def test_describe_fails_a_broken_signature() -> None:
    provider = _Provider()
    data = provider.sign(_content([_entry(_self_signed())]), signed_payload=b"other")
    ok, report = _describe(data, provider.ca)
    assert not ok
    assert "[ok] signer is" in report
    assert "[ok] signature verifies" not in report


def test_describe_fails_a_file_that_is_not_a_vical() -> None:
    ok, report = _describe(TRUNCATED, _Provider().ca)
    assert not ok
    assert "signer:" not in report and report.endswith("\nNOT TRUSTED")


@pytest.mark.parametrize("field", ["nextUpdate", "notAfter"])
def test_describe_fails_a_list_past_its_dates(field: str) -> None:
    provider = _Provider()
    content = _content([_entry(_self_signed())], **{field: NOW - timedelta(seconds=1)})
    ok, report = _describe(provider.sign(content), provider.ca)
    assert not ok
    assert f"[FAIL] {field}" in report and "has passed" in report
    assert "issuers: 1" in report  # the issuers are still listed


def test_describe_fails_a_date_that_is_not_a_date_and_notes_no_next_update() -> None:
    provider = _Provider()
    content = _content([_entry(_self_signed())], nextUpdate=None, notAfter="soon")
    ok, report = _describe(provider.sign(content), provider.ca)
    assert not ok
    assert "[note] no nextUpdate" in report
    assert "[FAIL] VICAL test-vical" in report


def test_describe_fails_a_list_without_certificate_infos() -> None:
    provider = _Provider()
    ok, report = _describe(provider.sign(_content([], certificateInfos=None)), provider.ca)
    assert not ok
    assert "[FAIL] no certificateInfos list" in report
