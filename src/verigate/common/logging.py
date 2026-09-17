"""structlog configuration: JSON lines in CI/containers, coloured key=value on a dev laptop.

Usage::

    from verigate.common.logging import configure_logging, get_logger
    configure_logging(settings)
    log = get_logger(__name__)
    log.info("stage1.check", check="expiry", release_id=rid, ok=False)

Event names are dotted, lower-case, stable strings (the dashboard filters on them); details go in
key/value pairs — never in f-strings.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

from verigate.common.settings import Settings

_LEVELS = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}


def configure_logging(settings: Settings) -> None:
    """Configure structlog + stdlib logging once per process. Idempotent."""
    level = _LEVELS.get(settings.log_level.upper(), logging.INFO)
    shared: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    renderer: Any = (
        structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())
        if settings.is_dev
        else structlog.processors.JSONRenderer()
    )
    structlog.configure(
        processors=[*shared, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=False,
    )
    logging.basicConfig(level=level, stream=sys.stderr, format="%(message)s", force=True)


def get_logger(name: str) -> structlog.typing.FilteringBoundLogger:
    """Return a bound logger tagged with ``module=name``."""
    logger: structlog.typing.FilteringBoundLogger = structlog.get_logger().bind(module=name)
    return logger
