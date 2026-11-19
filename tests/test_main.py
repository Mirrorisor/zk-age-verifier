import os
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives.serialization import Encoding

from tests.conftest import render_config
from tests.core.test_trustlist import _self_signed
from tests.core.test_vical import _content, _entry, _Provider
from zk_age_verifier import __main__
from zk_age_verifier.__main__ import _serve, main
from zk_age_verifier.app import CONFIG_ENV_VAR

CREDENTIALS = Path(__file__).parent / "integration" / "credentials"


@pytest.fixture(autouse=True)
def _clean_config_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.delenv(CONFIG_ENV_VAR, raising=False)
    yield


def test_main_serves_validated_config(config_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, int]] = []
    monkeypatch.setattr(__main__, "_serve", lambda host, port: calls.append((host, port)))
    main(["--config", str(config_file), "--host", "0.0.0.0", "--port", "9000"])
    assert calls == [("0.0.0.0", 9000)]
    assert os.environ[CONFIG_ENV_VAR] == str(config_file.resolve())


def test_main_defaults(config_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, int]] = []
    monkeypatch.setattr(__main__, "_serve", lambda host, port: calls.append((host, port)))
    main(["--config", str(config_file)])
    assert calls == [("127.0.0.1", 8000)]


def test_main_rejects_bad_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(__main__, "_serve", lambda host, port: None)
    with pytest.raises(SystemExit):
        main(["--config", str(tmp_path / "missing.toml")])
    assert CONFIG_ENV_VAR not in os.environ


def test_check_cert_trusted_exits_zero(
    config_file: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    served: list[tuple[str, int]] = []
    monkeypatch.setattr(__main__, "_serve", lambda host, port: served.append((host, port)))
    leaf = CREDENTIALS / "eu-av-vendored" / "leaf.pem"
    with pytest.raises(SystemExit) as stop:
        main(["--config", str(config_file), "--check-cert", str(leaf)])
    assert stop.value.code == 0
    assert "verdict: TRUSTED" in capsys.readouterr().out
    assert served == []  # checking a certificate never starts the server


def test_check_cert_untrusted_exits_one(
    config_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    leaf = CREDENTIALS / "eu-av-untrusted" / "leaf.pem"  # signed by a CA the config lacks
    with pytest.raises(SystemExit) as stop:
        main(["--config", str(config_file), "--check-cert", str(leaf)])
    assert stop.value.code == 1
    assert "verdict: NOT TRUSTED" in capsys.readouterr().out


def test_check_cert_reports_bad_input_with_exit_two(
    config_file: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as stop:
        main(["--config", str(config_file), "--check-cert", str(tmp_path / "missing.pem")])
    assert stop.value.code == 2
    assert "cannot read" in capsys.readouterr().err


def _vical_files(tmp_path: Path, provider: _Provider) -> tuple[str, str]:
    """Write a VICAL signed by ``provider`` and its root's PEM; return both paths."""
    vical, root = tmp_path / "vical.cbor", tmp_path / "vical-root.pem"
    vical.write_bytes(provider.sign(_content([_entry(_self_signed("listed-root"))])))
    root.write_bytes(provider.ca.public_bytes(Encoding.PEM))
    return str(vical), str(root)


def test_check_vical_trusted_exits_zero_without_a_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    served: list[tuple[str, int]] = []
    monkeypatch.setattr(__main__, "_serve", lambda host, port: served.append((host, port)))
    vical, root = _vical_files(tmp_path, _Provider())
    with pytest.raises(SystemExit) as stop:
        main(["--check-vical", vical, "--vical-signer", root])
    assert stop.value.code == 0
    out = capsys.readouterr().out
    assert "CN=listed-root" in out and out.endswith("TRUSTED\n")
    assert served == []  # checking a list never starts the server


def test_check_vical_from_another_signer_exits_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    vical, _ = _vical_files(tmp_path, _Provider())
    other = tmp_path / "other"
    other.mkdir()
    _, other_root = _vical_files(other, _Provider())
    with pytest.raises(SystemExit) as stop:
        main(["--check-vical", vical, "--vical-signer", other_root])
    assert stop.value.code == 1
    assert capsys.readouterr().out.endswith("NOT TRUSTED\n")


def test_check_vical_reports_bad_input_with_exit_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, root = _vical_files(tmp_path, _Provider())
    with pytest.raises(SystemExit) as stop:
        main(["--check-vical", str(tmp_path / "missing.cbor"), "--vical-signer", root])
    assert stop.value.code == 2
    assert "cannot read trust list" in capsys.readouterr().err


def test_check_vical_needs_a_signer(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stop:
        main(["--check-vical", "vical.cbor"])
    assert stop.value.code == 2
    assert "--check-vical needs --vical-signer" in capsys.readouterr().err


def test_main_without_a_config_is_an_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as stop:
        main([])
    assert stop.value.code == 2
    assert "--config is required" in capsys.readouterr().err


def test_main_rejects_bad_log_level(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(__main__, "_serve", lambda host, port: None)
    path = tmp_path / "config.toml"
    path.write_text(render_config(log_level="verbose"))
    with pytest.raises(SystemExit):
        main(["--config", str(path)])
    assert "log_level" in capsys.readouterr().err
    assert CONFIG_ENV_VAR not in os.environ


def test_serve_boots_granian(monkeypatch: pytest.MonkeyPatch) -> None:
    granian = MagicMock()
    monkeypatch.setattr(__main__, "Granian", granian)
    _serve("127.0.0.1", 8000)
    granian.assert_called_once()
    assert granian.call_args.kwargs["factory"] is True
    granian.return_value.serve.assert_called_once_with()
