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


class _StderrLogger:
    """Writes one rendered line to whatever ``sys.stderr`` is *now* (test runners swap it)."""

    def msg(self, message: str) -> None:
        sys.stderr.write(message + "\n")
        sys.stderr.flush()

    log = debug = info = warning = error = critical = msg


def _stderr_factory(*_args: Any) -> _StderrLogger:
    return _StderrLogger()


def configure_logging(settings: Settings, extra_processors: list[Any] | None = None) -> None:
    """Configure structlog + stdlib logging once per process. Idempotent.

    Args:
        settings: Supplies ``log_level`` and dev/CI mode.
        extra_processors: Appended after the standard chain (the gateway adds its log hub here).
    """
    level = _LEVELS.get(settings.log_level.upper(), logging.INFO)
    shared: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        *(extra_processors or []),
    ]
    renderer: Any = (
        structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())
        if settings.is_dev
        else structlog.processors.JSONRenderer()
    )
    structlog.configure(
        processors=[*shared, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=_stderr_factory,
        cache_logger_on_first_use=False,
    )
    logging.basicConfig(level=level, stream=sys.stderr, format="%(message)s", force=True)
    for noisy in ("httpx", "httpcore", "web3", "urllib3", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.typing.FilteringBoundLogger:
    """Return a lazy logger tagged with ``module=name``.

    Lazy on purpose: module-level ``log = get_logger(__name__)`` must pick up the configuration
    applied later by :func:`configure_logging` (the proxy resolves on first use).
    """
    logger: structlog.typing.FilteringBoundLogger = structlog.get_logger(module=name)
    return logger
