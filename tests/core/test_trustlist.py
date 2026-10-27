import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from structlog.testing import capture_logs

from zk_age_verifier.config import ConfigError, TrustSource
from zk_age_verifier.core import trustlist
from zk_age_verifier.core.trustlist import AnchorSet, UntrustedIssuer, load_anchors

# The test CA and the upstream test-issuer key its vendored leaf certifies.
TEST_ANCHOR_PEM = Path(__file__).parents[1] / "integration" / "credentials" / "test-anchor.pem"
VENDORED_ISSUER_X = 0xB4682EC20E06E8DF840B5DD32959798AB20C544D4DA50109FF4684D06FD261FC

# Real certificates, not ones this suite builds. See tests/data/README.md.
AV_ISSUER_CA_PEM = Path(__file__).parents[1] / "data" / "av-issuer-ca-01.pem"
AV_DOCUMENT_SIGNER_PEM = Path(__file__).parents[1] / "data" / "av-document-signer-001.pem"
AV_DOCUMENT_SIGNER_X = 0x6789E96E797E2E04F7F3CBB54A12410412410DB000FB6D63DC977D8B5D35A4F9

NOW = datetime.now(UTC)


def _key_usage(*, digital_signature: bool = False, key_cert_sign: bool = False) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=digital_signature,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=key_cert_sign,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )


def _cert(
    key: ec.EllipticCurvePrivateKey,
    subject: str,
    issuer: str,
    signer: ec.EllipticCurvePrivateKey,
    *,
    ca: bool = False,
    not_after: datetime | None = None,
    key_usage: x509.KeyUsage | None = None,
    with_key_usage: bool = True,
    critical: bool = True,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(not_after or NOW + timedelta(days=365))
    )
    if with_key_usage:
        usage = key_usage or _key_usage(digital_signature=not ca, key_cert_sign=ca)
        builder = builder.add_extension(usage, critical=critical)
    if ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
    return builder.sign(signer, hashes.SHA256())


def _self_signed(subject: str = "anchor", not_after: datetime | None = None) -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    return _cert(
        key,
        subject,
        subject,
        key,
        ca=True,
        not_after=not_after,
        key_usage=_key_usage(digital_signature=True, key_cert_sign=True),
    )


def _xy(key: ec.EllipticCurvePrivateKey) -> tuple[int, int]:
    numbers = key.public_key().public_numbers()
    return numbers.x, numbers.y


def test_exact_match_accepted() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    anchor = _cert(
        key,
        "anchor",
        "anchor",
        key,
        ca=True,
        key_usage=_key_usage(digital_signature=True, key_cert_sign=True),
    )
    assert AnchorSet((anchor,)).resolve(anchor) == _xy(key)


def test_chained_leaf_accepted() -> None:
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = _cert(ca_key, "CA", "CA", ca_key, ca=True)
    ds_key = ec.generate_private_key(ec.SECP256R1())
    ds = _cert(ds_key, "DS", "CA", ca_key)
    assert AnchorSet((ca,)).resolve(ds) == _xy(ds_key)


def test_leaf_without_key_usage_rejected() -> None:
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = _cert(ca_key, "CA", "CA", ca_key, ca=True)
    ds_key = ec.generate_private_key(ec.SECP256R1())
    ds = _cert(ds_key, "DS", "CA", ca_key, with_key_usage=False)
    with pytest.raises(UntrustedIssuer):
        AnchorSet((ca,)).resolve(ds)


def test_leaf_without_digital_signature_rejected() -> None:
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = _cert(ca_key, "CA", "CA", ca_key, ca=True)
    ds_key = ec.generate_private_key(ec.SECP256R1())
    ds = _cert(ds_key, "DS", "CA", ca_key, key_usage=_key_usage(key_cert_sign=True))
    with pytest.raises(UntrustedIssuer):
        AnchorSet((ca,)).resolve(ds)


def test_chained_anchor_without_key_cert_sign_rejected() -> None:
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = _cert(ca_key, "CA", "CA", ca_key, ca=True, key_usage=_key_usage(digital_signature=True))
    ds_key = ec.generate_private_key(ec.SECP256R1())
    ds = _cert(ds_key, "DS", "CA", ca_key)
    with pytest.raises(UntrustedIssuer):
        AnchorSet((ca,)).resolve(ds)


def test_unrelated_cert_rejected() -> None:
    with pytest.raises(UntrustedIssuer):
        AnchorSet((_self_signed(),)).resolve(_self_signed("stranger"))


def test_untrusted_issuer_logs_presented_certificate() -> None:
    stranger = _self_signed("stranger")
    with capture_logs() as logs, pytest.raises(UntrustedIssuer):
        AnchorSet((_self_signed(),)).resolve(stranger)
    (event,) = [entry for entry in logs if entry["event"] == "untrusted_issuer"]
    assert event["log_level"] == "warning"
    assert event["subject"] == "CN=stranger"
    assert event["sha256"] == stranger.fingerprint(hashes.SHA256()).hex()


def test_expired_anchor_rejected() -> None:
    expired = _self_signed(not_after=NOW - timedelta(days=1))
    with pytest.raises(UntrustedIssuer):
        AnchorSet((expired,)).resolve(expired)


def test_non_p256_key_rejected() -> None:
    key = ec.generate_private_key(ec.SECP384R1())
    cert = _cert(
        key,
        "p384",
        "p384",
        key,
        ca=True,
        key_usage=_key_usage(digital_signature=True, key_cert_sign=True),
    )
    with pytest.raises(UntrustedIssuer):
        AnchorSet((cert,)).resolve(cert)


class _FrozenDatetime(datetime):
    """``datetime`` whose ``now()`` is a day inside the real document signer's validity."""

    @classmethod
    def now(cls, tz=None):  # type: ignore[no-untyped-def]
        return datetime(2026, 7, 1, tzinfo=UTC)


def test_real_document_signer_resolves_through_real_anchor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The real document signer is valid only until 2026-09-24, so the clock is
    # pinned to a day inside its validity. Without this the test starts failing
    # the day the certificate expires.
    monkeypatch.setattr(trustlist, "datetime", _FrozenDatetime)
    anchor = x509.load_pem_x509_certificate(AV_ISSUER_CA_PEM.read_bytes())
    signer = x509.load_pem_x509_certificate(AV_DOCUMENT_SIGNER_PEM.read_bytes())
    with capture_logs() as logs:
        x, _ = AnchorSet((anchor,)).resolve(signer)
    assert x == AV_DOCUMENT_SIGNER_X
    fallbacks = [entry for entry in logs if entry["event"] == "key_usage_der_fallback"]
    assert fallbacks
    assert fallbacks[0]["error"]


def test_unreadable_key_usage_rejected() -> None:
    """A certificate whose keyUsage content the fallback cannot read is rejected."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = _cert(ca_key, "CA", "CA", ca_key, ca=True)
    ds_key = ec.generate_private_key(ec.SECP256R1())
    ds = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DS")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CA")]))
        .public_key(ds_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=365))
        .add_extension(
            x509.UnrecognizedExtension(x509.oid.ExtensionOID.KEY_USAGE, b""), critical=True
        )
        .sign(ca_key, hashes.SHA256())
    )
    with capture_logs() as logs:
        with pytest.raises(UntrustedIssuer):
            AnchorSet((ca,)).resolve(ds)
    assert any(entry["event"] == "key_usage_unreadable" for entry in logs)


def test_real_issuer_ca_rejected() -> None:
    # https://github.com/pipe23-org/zk-age-verifier/issues/35
    ca = x509.load_pem_x509_certificate(AV_ISSUER_CA_PEM.read_bytes())
    with pytest.raises(UntrustedIssuer):
        AnchorSet((ca,)).resolve(ca)


def test_der_fallback_agrees_with_pyca() -> None:
    """_key_usage_from_tbs() must agree with cryptography's KeyUsage parse."""
    key = ec.generate_private_key(ec.SECP256R1())
    certs = [
        _cert(key, "ca", "ca", key, ca=True),
        _cert(key, "leaf", "ca", key),
        _cert(
            key,
            "both",
            "both",
            key,
            key_usage=_key_usage(digital_signature=True, key_cert_sign=True),
        ),
        _cert(key, "all-false", "ca", key, key_usage=_key_usage()),
        _cert(key, "non-critical", "ca", key, critical=False),
        _cert(key, "no-extensions", "ca", key, with_key_usage=False),
        _cert(key, "no-key-usage", "ca", key, ca=True, with_key_usage=False),
    ]
    for cert in certs:
        for bit in ("digital_signature", "key_cert_sign"):
            try:
                extension = cert.extensions.get_extension_for_class(x509.KeyUsage)
                expected = getattr(extension.value, bit)
            except x509.ExtensionNotFound:
                expected = False
            assert trustlist._key_usage_from_tbs(cert.tbs_certificate_bytes, bit) == expected


def test_committed_credential_leaf_resolves_through_committed_anchor() -> None:
    anchors = load_anchors([TrustSource(pem=str(TEST_ANCHOR_PEM))])
    leaf = x509.load_pem_x509_certificate(
        (TEST_ANCHOR_PEM.parent / "eu-av-vendored" / "leaf.pem").read_bytes()
    )
    x, _ = anchors.resolve(leaf)
    assert x == VENDORED_ISSUER_X


def test_pem_file_source(tmp_path: Path) -> None:
    anchor = _self_signed()
    pem = tmp_path / "anchor.pem"
    pem.write_bytes(anchor.public_bytes(Encoding.PEM))
    anchors = load_anchors([TrustSource(pem=str(pem))])
    assert anchors.resolve(anchor)


def test_pem_directory_source(tmp_path: Path) -> None:
    first, second = _self_signed("one"), _self_signed("two")
    (tmp_path / "one.pem").write_bytes(first.public_bytes(Encoding.PEM))
    (tmp_path / "two.pem").write_bytes(second.public_bytes(Encoding.PEM))
    (tmp_path / "notes.txt").write_text("ignored")
    anchors = load_anchors([TrustSource(pem=str(tmp_path))])
    assert len(anchors.anchors) == 2


def test_empty_anchor_set_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="no anchors"):
        load_anchors([TrustSource(pem=str(tmp_path))])


def _etsi_xml(*certs: x509.Certificate) -> bytes:
    entries = "".join(
        "<X509Certificate>\n"
        + base64.b64encode(cert.public_bytes(Encoding.DER)).decode("ascii")
        + "\n</X509Certificate>"
        for cert in certs
    )
    return (
        '<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">'
        f"{entries}</TrustServiceStatusList>"
    ).encode("ascii")


def test_etsi_xml_path_source(tmp_path: Path) -> None:
    anchor = _self_signed()
    listing = tmp_path / "tsl.xml"
    listing.write_bytes(_etsi_xml(anchor))
    anchors = load_anchors([TrustSource(etsi_xml=str(listing))])
    assert anchors.resolve(anchor)


def test_etsi_xml_url_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    anchor = _self_signed()
    xml = _etsi_xml(anchor)

    class _Response:
        def __enter__(self) -> "_Response":
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def read(self) -> bytes:
            return xml

    monkeypatch.setattr(trustlist, "urlopen", lambda _url: _Response())
    anchors = load_anchors([TrustSource(etsi_xml="https://tsl.example.org/list.xml")])
    assert anchors.resolve(anchor)


def test_etsi_xml_http_url_rejected() -> None:
    with pytest.raises(ConfigError, match="http"):
        load_anchors([TrustSource(etsi_xml="http://tsl.example.org/list.xml")])
