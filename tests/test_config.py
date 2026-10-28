from pathlib import Path

import pytest
from pydantic import ValidationError

from zk_age_verifier.config import (
    Config,
    ConfigError,
    ServiceConfig,
    TrustSource,
    load_config,
)
from zk_age_verifier.core.constants import EU_AV, ISO_MDL

PREFIX = "ZK_AGE_VERIFIER_"

BASE_CONFIG = (
    "[service]\n"
    'expected_origin = "https://chat.example.org"\n'
    "session_ttl_seconds = 300\n"
    "session_cap = 1000\n"
    "[trust]\n"
    'sources = [{ pem = "/etc/anchors" }]\n'
)


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "c.toml"
    path.write_text(body)
    return path


def test_load_defaults(config_file: Path) -> None:
    config = load_config(config_file)
    assert config.service.expected_origin == "https://chat.example.org"
    assert config.service.session_ttl_seconds == 300
    assert config.service.session_cap == 1000
    assert config.service.timestamp_skew_seconds == 300
    assert config.service.cors_allowed_origins == []
    pem = config.trust.sources[0].pem
    assert pem is not None and pem.endswith("test-anchor.pem")


def test_credential_defaults_to_the_eu_age_verification_profile(tmp_path: Path) -> None:
    config = load_config(_write(tmp_path, BASE_CONFIG))
    assert config.service.credential == "eu-av"
    assert config.service.profile is EU_AV


def test_credential_selects_the_iso_driving_licence_profile(tmp_path: Path) -> None:
    body = BASE_CONFIG.replace("[trust]", 'credential = "iso-mdl"\n[trust]')
    config = load_config(_write(tmp_path, body))
    assert config.service.profile is ISO_MDL


def test_credential_can_come_from_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(f"{PREFIX}SERVICE__CREDENTIAL", "iso-mdl")
    config = load_config(_write(tmp_path, BASE_CONFIG))
    assert config.service.profile is ISO_MDL


def test_unknown_credential_is_rejected_and_the_choices_are_named() -> None:
    with pytest.raises(ValidationError, match="credential must be one of"):
        ServiceConfig(expected_origin="https://chat.example.org", credential="passport")


def test_timestamp_skew_override(tmp_path: Path) -> None:
    body = (
        "[service]\n"
        'expected_origin = "https://host"\n'
        "timestamp_skew_seconds = 30\n"
        "[trust]\n"
        'sources = [{ pem = "/etc/anchors" }]\n'
    )
    config = load_config(_write(tmp_path, body))
    assert config.service.timestamp_skew_seconds == 30


def test_load_overrides(tmp_path: Path) -> None:
    path = tmp_path / "c.toml"
    path.write_text(
        "[service]\n"
        'expected_origin = "http://localhost:8000"\n'
        "session_ttl_seconds = 60\n"
        "session_cap = 5\n"
        'cors_allowed_origins = ["https://a.example"]\n'
        "[trust]\n"
        'sources = [{ pem = "/etc/anchors" }, { etsi_xml = "https://x/list.xml" }]\n'
    )
    config = load_config(path)
    assert config.service.session_ttl_seconds == 60
    assert config.service.session_cap == 5
    assert config.service.cors_allowed_origins == ["https://a.example"]
    assert config.trust.sources[1].etsi_xml == "https://x/list.xml"


def test_env_overrides_toml_scalar(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(f"{PREFIX}SERVICE__SESSION_CAP", "5")
    config = load_config(_write(tmp_path, BASE_CONFIG))
    assert config.service.session_cap == 5


def test_unknown_top_level_prefixed_env_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Pins the coupling CONFIG_ENV_VAR relies on: the file locator shares the
    # value-override prefix and must be ignored by the loader.
    monkeypatch.setenv(f"{PREFIX}TOTALLY_BOGUS", "1")
    config = load_config(_write(tmp_path, BASE_CONFIG))
    assert config.service.session_cap == 1000


def test_capitalised_toml_table_rejected(tmp_path: Path) -> None:
    body = BASE_CONFIG.replace("[service]", "[Service]")
    with pytest.raises(ConfigError, match="invalid configuration"):
        load_config(_write(tmp_path, body))


def test_capitalised_toml_key_rejected(tmp_path: Path) -> None:
    body = BASE_CONFIG.replace("session_cap", "Session_Cap")
    with pytest.raises(ConfigError, match="invalid configuration"):
        load_config(_write(tmp_path, body))


def test_unknown_prefixed_env_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(f"{PREFIX}SERVICE__BOGUS", "1")
    with pytest.raises(ConfigError, match="invalid configuration"):
        load_config(_write(tmp_path, BASE_CONFIG))


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.toml")


def test_invalid_toml(tmp_path: Path) -> None:
    path = tmp_path / "bad.toml"
    path.write_text("this is = = not toml")
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_config(path)


def test_validation_failure(tmp_path: Path) -> None:
    path = tmp_path / "bad.toml"
    path.write_text('[trust]\nsources = [{ pem = "/etc/anchors" }]\n')  # no [service]
    with pytest.raises(ConfigError, match="invalid configuration"):
        load_config(path)


@pytest.mark.parametrize("origin", ["https://chat.example.org", "http://localhost:8000"])
def test_valid_origin(origin: str) -> None:
    assert ServiceConfig(expected_origin=origin).expected_origin == origin


@pytest.mark.parametrize(
    "origin",
    [
        "ftp://host",
        "chat.example.org",
        "https://",
        "https://host/",
        "https://host?q=1",
        "https://host#frag",
    ],
)
def test_bad_origin(origin: str) -> None:
    with pytest.raises(ValidationError):
        ServiceConfig(expected_origin=origin)


def test_service_forbids_unknown_key() -> None:
    with pytest.raises(ValidationError):
        ServiceConfig.model_validate({"expected_origin": "https://host", "bogus": 1})


@pytest.mark.parametrize(
    "kwargs",
    [
        {"pem": "/etc/anchors"},
        {"etsi_xml": "https://x/list.xml"},
        {"etsi_xml": "https://x/list.xml", "etsi_xml_sha256": "ab" * 32},
        {"etsi_xml": "https://x/list.xml", "etsi_xml_signer": "/etc/list-signer.pem"},
        {
            "etsi_lotl": "https://x/lotl.xml",
            "etsi_lotl_signer": "/etc/lotl-signer.pem",
            "etsi_lotl_territories": ["EE", "lv"],
        },
    ],
)
def test_valid_trust_source(kwargs: dict[str, object]) -> None:
    source = TrustSource(**kwargs)
    assert source.model_dump(exclude_none=True) == kwargs


@pytest.mark.parametrize(
    "kwargs",
    [
        {},  # zero keys
        {"pem": "/etc/anchors", "etsi_xml": "https://x/list.xml"},  # two keys
        {"pem": "/etc/anchors", "etsi_xml_sha256": "ab" * 32},  # a pin needs a list
        {"etsi_xml": "https://x/list.xml", "etsi_xml_sha256": "xyz"},  # not a SHA-256
        {"pem": "/etc/anchors", "etsi_xml_signer": "/etc/list-signer.pem"},  # a signer needs a list
        {"etsi_lotl": "https://x/l.xml", "etsi_lotl_territories": ["EE"]},  # no signer
        {"etsi_lotl": "https://x/l.xml", "etsi_lotl_signer": "/s.pem"},  # no territories
        {"etsi_lotl": "https://x/l.xml", "etsi_lotl_signer": "/s.pem", "etsi_lotl_territories": []},
        {
            "etsi_lotl": "https://x/l.xml",
            "etsi_lotl_signer": "/s.pem",
            "etsi_lotl_territories": ["EST"],  # not a two-letter code
        },
        {"etsi_lotl_signer": "/s.pem"},  # a signer needs a list of trusted lists
        {"etsi_lotl_territories": ["EE"], "pem": "/etc/anchors"},  # territories need one too
        {
            "pem": "/etc/anchors",
            "etsi_lotl": "https://x/l.xml",
            "etsi_lotl_signer": "/s.pem",
            "etsi_lotl_territories": ["EE"],
        },  # two keys
    ],
)
def test_bad_trust_source(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        TrustSource(**kwargs)


def test_empty_sources_rejected() -> None:
    with pytest.raises(ValidationError):
        Config.model_validate(
            {"service": {"expected_origin": "https://host"}, "trust": {"sources": []}}
        )
