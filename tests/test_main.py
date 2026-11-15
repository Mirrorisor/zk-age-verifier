import os
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from tests.conftest import render_config
from zk_age_verifier import __main__
from zk_age_verifier.__main__ import _serve, main
from zk_age_verifier.app import CONFIG_ENV_VAR


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
