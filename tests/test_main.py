import os
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import MagicMock

import pytest

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


def test_serve_boots_granian(monkeypatch: pytest.MonkeyPatch) -> None:
    granian = MagicMock()
    monkeypatch.setattr(__main__, "Granian", granian)
    _serve("127.0.0.1", 8000)
    granian.assert_called_once()
    assert granian.call_args.kwargs["factory"] is True
    granian.return_value.serve.assert_called_once_with()
