import json
import logging

import pytest
import structlog

from zk_age_verifier.log import configure_logging


def test_json_by_default(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("LOG_FORMAT", raising=False)
    configure_logging("info")
    structlog.get_logger().info("something-happened", answer=42)
    record = json.loads(capsys.readouterr().err)
    assert record["event"] == "something-happened"
    assert record["answer"] == 42
    assert record["level"] == "info"


def test_console_renderer_in_dev(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LOG_FORMAT", "console")
    configure_logging("info")
    structlog.get_logger().info("something-happened", answer=42)
    err = capsys.readouterr().err
    assert "something-happened" in err
    with pytest.raises(json.JSONDecodeError):
        json.loads(err)


def test_json_carries_the_logged_exception_traceback(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("LOG_FORMAT", raising=False)
    configure_logging("info")
    try:
        raise ValueError("boom")
    except ValueError:
        structlog.get_logger().exception("engine-error")
    record = json.loads(capsys.readouterr().err)
    assert record["event"] == "engine-error"
    assert "ValueError: boom" in record["exception"]
    assert "exc_info" not in record


def test_stdlib_logs_join_the_stream(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("LOG_FORMAT", raising=False)
    configure_logging("info")
    logging.getLogger("uvicorn.error").info("server started")
    record = json.loads(capsys.readouterr().err)
    assert record["event"] == "server started"
    assert record["level"] == "info"


def test_debug_dropped_at_info(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("LOG_FORMAT", raising=False)
    configure_logging("info")
    structlog.get_logger().debug("something-happened")
    assert capsys.readouterr().err == ""


def test_debug_emitted_at_debug(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("LOG_FORMAT", raising=False)
    configure_logging("debug")
    structlog.get_logger().debug("something-happened", answer=42)
    record = json.loads(capsys.readouterr().err)
    assert record["event"] == "something-happened"
    assert record["level"] == "debug"


def test_info_dropped_at_warning(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("LOG_FORMAT", raising=False)
    configure_logging("warning")
    structlog.get_logger().info("something-happened")
    assert capsys.readouterr().err == ""


def test_warning_dropped_at_error(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("LOG_FORMAT", raising=False)
    configure_logging("error")
    structlog.get_logger().warning("something-happened")
    assert capsys.readouterr().err == ""
