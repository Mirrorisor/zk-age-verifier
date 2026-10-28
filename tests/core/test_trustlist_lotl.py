"""A signed list of trusted lists passes trust to the national lists it points to."""

from pathlib import Path

import pytest
from cryptography import x509
from structlog.testing import capture_logs

from tests.core.test_trustlist import _b64_der, _etsi_xml, _self_signed
from tests.core.test_trustlist_signature import _Signer, _write
from zk_age_verifier.config import ConfigError, TrustSource
from zk_age_verifier.core import trustlist
from zk_age_verifier.core.trustlist import load_anchors

XML_MIME = "application/vnd.etsi.tsl+xml"
LOTL_URL = "https://lotl.example.org/lotl.xml"
EE_URL = "https://tsl.example.ee/tsl.xml"
LV_URL = "https://tsl.example.lv/tsl.xml"
FUTURE = "<dateTime>2999-01-01T00:00:00Z</dateTime>"
PAST = "<dateTime>2000-01-01T00:00:00Z</dateTime>"


def _pointer(
    territory: str,
    location: str,
    certs: list[x509.Certificate],
    mime: str = XML_MIME,
) -> str:
    """One ``OtherTSLPointer``: where a national list is, and who signs it."""
    identities = "".join(
        f"<ServiceDigitalIdentity><DigitalId><X509Certificate>{_b64_der(cert)}"
        "</X509Certificate></DigitalId></ServiceDigitalIdentity>"
        for cert in certs
    )
    return (
        f"<OtherTSLPointer><ServiceDigitalIdentities>{identities}</ServiceDigitalIdentities>"
        f"<TSLLocation>{location}</TSLLocation><AdditionalInformation>"
        f"<OtherInformation><SchemeTerritory>{territory}</SchemeTerritory></OtherInformation>"
        '<OtherInformation><MimeType xmlns="http://uri.etsi.org/02231/v2/additionaltypes#">'
        f"{mime}</MimeType></OtherInformation></AdditionalInformation></OtherTSLPointer>"
    )


def _lotl(*pointers: str, next_update: str = FUTURE) -> bytes:
    """A list of trusted lists holding the given pointers."""
    return (
        '<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#"><SchemeInformation>'
        f"<NextUpdate>{next_update}</NextUpdate>"
        f"<PointersToOtherTSL>{''.join(pointers)}</PointersToOtherTSL>"
        "</SchemeInformation></TrustServiceStatusList>"
    ).encode("ascii")


def _serve(monkeypatch: pytest.MonkeyPatch, files: dict[str, bytes]) -> list[str]:
    """Answer https fetches from ``files``; return the list of URLs asked for."""
    asked: list[str] = []

    class _Response:
        def __init__(self, data: bytes) -> None:
            self.data = data

        def __enter__(self) -> "_Response":
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def read(self) -> bytes:
            return self.data

    def urlopen(url: str) -> _Response:
        asked.append(url)
        if url not in files:
            raise OSError("no route to host")
        return _Response(files[url])

    monkeypatch.setattr(trustlist, "urlopen", urlopen)
    return asked


def _source(tmp_path: Path, lotl_signer: _Signer, *territories: str) -> TrustSource:
    return TrustSource(
        etsi_lotl=LOTL_URL,
        etsi_lotl_signer=str(lotl_signer.pem),
        etsi_lotl_territories=list(territories),
    )


def test_the_chosen_territories_lists_become_anchors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lotl_signer, ee_signer = _Signer(tmp_path, "lotl"), _Signer(tmp_path, "ee")
    lv_signer = _Signer(tmp_path, "lv")
    ee_anchor, lv_anchor = _self_signed("ee-anchor"), _self_signed("lv-anchor")
    asked = _serve(
        monkeypatch,
        {
            LOTL_URL: lotl_signer.sign(
                _lotl(
                    _pointer("EE", EE_URL, [ee_signer.cert]),
                    _pointer("LV", LV_URL, [lv_signer.cert]),
                    _pointer(
                        "DE", "https://never.example.org/", [ee_signer.cert], mime="text/html"
                    ),
                )
            ),
            EE_URL: ee_signer.sign(_etsi_xml(ee_anchor, next_update=FUTURE)),
            LV_URL: lv_signer.sign(_etsi_xml(lv_anchor)),
        },
    )
    with capture_logs() as logs:
        anchors = load_anchors([_source(tmp_path, lotl_signer, "ee")])
    assert anchors.resolve(ee_anchor)
    with pytest.raises(trustlist.UntrustedIssuer):
        anchors.resolve(lv_anchor)
    assert asked == [LOTL_URL, EE_URL]  # Latvia was not asked for
    (loaded,) = [entry for entry in logs if entry["event"] == "etsi_lotl_list_loaded"]
    assert (loaded["territory"], loaded["anchors"]) == ("EE", 1)


def test_territory_codes_are_not_case_sensitive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lotl_signer, ee_signer = _Signer(tmp_path, "lotl"), _Signer(tmp_path, "ee")
    anchor = _self_signed()
    _serve(
        monkeypatch,
        {
            LOTL_URL: lotl_signer.sign(_lotl(_pointer("ee", EE_URL, [ee_signer.cert]))),
            EE_URL: ee_signer.sign(_etsi_xml(anchor)),
        },
    )
    assert load_anchors([_source(tmp_path, lotl_signer, "EE", "ee")]).resolve(anchor)


def test_a_national_list_may_be_signed_by_any_certificate_in_its_pointer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lotl_signer, old, new = (
        _Signer(tmp_path, "lotl"),
        _Signer(tmp_path, "old"),
        _Signer(tmp_path, "new"),
    )
    anchor = _self_signed()
    _serve(
        monkeypatch,
        {
            LOTL_URL: lotl_signer.sign(_lotl(_pointer("EE", EE_URL, [old.cert, new.cert]))),
            EE_URL: new.sign(_etsi_xml(anchor)),
        },
    )
    assert load_anchors([_source(tmp_path, lotl_signer, "EE")]).resolve(anchor)


def test_a_national_list_signed_by_someone_else_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lotl_signer, named, other = (
        _Signer(tmp_path, "lotl"),
        _Signer(tmp_path, "named"),
        _Signer(tmp_path, "other"),
    )
    _serve(
        monkeypatch,
        {
            LOTL_URL: lotl_signer.sign(_lotl(_pointer("EE", EE_URL, [named.cert]))),
            EE_URL: other.sign(_etsi_xml(_self_signed())),
        },
    )
    with pytest.raises(ConfigError, match="failed its signature check"):
        load_anchors([_source(tmp_path, lotl_signer, "EE")])


def test_a_pointer_without_certificates_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lotl_signer, ee_signer = _Signer(tmp_path, "lotl"), _Signer(tmp_path, "ee")
    _serve(
        monkeypatch,
        {
            LOTL_URL: lotl_signer.sign(_lotl(_pointer("EE", EE_URL, []))),
            EE_URL: ee_signer.sign(_etsi_xml(_self_signed())),
        },
    )
    with pytest.raises(ConfigError, match="names no signer certificate"):
        load_anchors([_source(tmp_path, lotl_signer, "EE")])


def test_an_unreadable_pointer_certificate_is_skipped_with_a_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lotl_signer, ee_signer = _Signer(tmp_path, "lotl"), _Signer(tmp_path, "ee")
    anchor = _self_signed()
    pointer = _pointer("EE", EE_URL, [ee_signer.cert]).replace(
        "</ServiceDigitalIdentities>",
        "<ServiceDigitalIdentity><DigitalId><X509Certificate>AAAA</X509Certificate>"
        "</DigitalId></ServiceDigitalIdentity></ServiceDigitalIdentities>",
    )
    _serve(
        monkeypatch,
        {
            LOTL_URL: lotl_signer.sign(_lotl(pointer)),
            EE_URL: ee_signer.sign(_etsi_xml(anchor)),
        },
    )
    with capture_logs() as logs:
        anchors = load_anchors([_source(tmp_path, lotl_signer, "EE")])
    assert anchors.resolve(anchor)
    assert [entry for entry in logs if entry["event"] == "etsi_lotl_bad_pointer_certificate"]


def test_a_territory_with_no_xml_list_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lotl_signer, ee_signer = _Signer(tmp_path, "lotl"), _Signer(tmp_path, "ee")
    _serve(
        monkeypatch,
        {
            LOTL_URL: lotl_signer.sign(
                _lotl(_pointer("EE", EE_URL, [ee_signer.cert], mime="text/html"))
            )
        },
    )
    with pytest.raises(ConfigError, match="no XML list for EE"):
        load_anchors([_source(tmp_path, lotl_signer, "EE")])


@pytest.mark.parametrize("location", ["http://tsl.example.ee/tsl.xml", "/etc/tsl.xml"])
def test_a_pointer_that_is_not_https_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, location: str
) -> None:
    lotl_signer, ee_signer = _Signer(tmp_path, "lotl"), _Signer(tmp_path, "ee")
    _serve(
        monkeypatch,
        {LOTL_URL: lotl_signer.sign(_lotl(_pointer("EE", location, [ee_signer.cert])))},
    )
    with pytest.raises(ConfigError, match="not an https address"):
        load_anchors([_source(tmp_path, lotl_signer, "EE")])


def test_a_list_of_trusted_lists_signed_by_someone_else_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    named, other, ee_signer = (
        _Signer(tmp_path, "named"),
        _Signer(tmp_path, "other"),
        _Signer(tmp_path, "ee"),
    )
    _serve(
        monkeypatch,
        {LOTL_URL: other.sign(_lotl(_pointer("EE", EE_URL, [ee_signer.cert])))},
    )
    with pytest.raises(ConfigError, match="failed its signature check"):
        load_anchors([_source(tmp_path, named, "EE")])


def test_a_stale_list_of_trusted_lists_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lotl_signer, ee_signer = _Signer(tmp_path, "lotl"), _Signer(tmp_path, "ee")
    _serve(
        monkeypatch,
        {
            LOTL_URL: lotl_signer.sign(
                _lotl(_pointer("EE", EE_URL, [ee_signer.cert]), next_update=PAST)
            )
        },
    )
    with pytest.raises(ConfigError, match="expired"):
        load_anchors([_source(tmp_path, lotl_signer, "EE")])


def test_a_stale_national_list_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lotl_signer, ee_signer = _Signer(tmp_path, "lotl"), _Signer(tmp_path, "ee")
    _serve(
        monkeypatch,
        {
            LOTL_URL: lotl_signer.sign(_lotl(_pointer("EE", EE_URL, [ee_signer.cert]))),
            EE_URL: ee_signer.sign(_etsi_xml(_self_signed(), next_update=PAST)),
        },
    )
    with pytest.raises(ConfigError, match="expired"):
        load_anchors([_source(tmp_path, lotl_signer, "EE")])


def test_a_list_of_trusted_lists_can_be_a_local_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lotl_signer, ee_signer = _Signer(tmp_path, "lotl"), _Signer(tmp_path, "ee")
    anchor = _self_signed()
    listing = _write(tmp_path, lotl_signer.sign(_lotl(_pointer("EE", EE_URL, [ee_signer.cert]))))
    _serve(monkeypatch, {EE_URL: ee_signer.sign(_etsi_xml(anchor))})
    source = TrustSource(
        etsi_lotl=str(listing),
        etsi_lotl_signer=str(lotl_signer.pem),
        etsi_lotl_territories=["EE"],
    )
    assert load_anchors([source]).resolve(anchor)


def test_a_national_list_that_cannot_be_fetched_stops_startup_cleanly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lotl_signer, ee_signer = _Signer(tmp_path, "lotl"), _Signer(tmp_path, "ee")
    pointer = _pointer("EE", EE_URL, [ee_signer.cert])
    _serve(monkeypatch, {LOTL_URL: lotl_signer.sign(_lotl(pointer))})  # EE_URL is unreachable
    with pytest.raises(ConfigError, match="cannot read trust list .*no route to host"):
        load_anchors([_source(tmp_path, lotl_signer, "EE")])


def test_a_missing_list_file_stops_startup_cleanly(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read trust list"):
        load_anchors([TrustSource(etsi_xml=str(tmp_path / "missing.xml"))])
