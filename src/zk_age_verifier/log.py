"""structlog configuration — call configure_logging() once at startup."""

import logging
import os
from typing import Literal

import structlog

LogLevel = Literal["debug", "info", "warning", "error"]
"""The thresholds the ``log_level`` configuration key accepts."""

_LEVELS: dict[LogLevel, int] = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
}


def configure_logging(level: LogLevel) -> None:
    """Configure structlog: JSON lines by default, pretty console when LOG_FORMAT=console.

    Stdlib logging is routed through the same renderer, so server and library
    logs come out in the one stream.

    Args:
        level: The threshold below which events are dropped.
    """
    processors: list[structlog.typing.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
    ]
    renderer: structlog.typing.Processor
    if os.environ.get("LOG_FORMAT") == "console":
        renderer = structlog.dev.ConsoleRenderer()
    else:
        processors.append(structlog.processors.format_exc_info)
        renderer = structlog.processors.JSONRenderer()
    structlog.configure(
        processors=[*processors, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=False,
    )
    handler = logging.StreamHandler()
    handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            foreign_pre_chain=processors,
            processors=[structlog.stdlib.ProcessorFormatter.remove_processors_meta, renderer],
        )
    )
    # force=True evicts handlers a server may already have installed on the root logger.
    logging.basicConfig(handlers=[handler], level=_LEVELS[level], force=True)
