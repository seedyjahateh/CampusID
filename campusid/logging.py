"""Structured logging setup.

Application logs are JSON so they are queryable alongside audit events. The
audit trail itself (FR-AUD-*) is a separate, durable store — not these logs.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog
from structlog.typing import FilteringBoundLogger

from campusid.config import Settings


def configure_logging(settings: Settings) -> None:
    """Configure structlog and route stdlib logging through it."""
    level = getattr(logging, settings.log_level)

    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    renderer: Any = (
        structlog.processors.JSONRenderer()
        if settings.log_format == "json"
        else structlog.dev.ConsoleRenderer()
    )

    structlog.configure(
        processors=[*shared_processors, structlog.processors.format_exc_info, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )

    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level)


def get_logger(name: str) -> FilteringBoundLogger:
    """Return a logger that tags every event with its originating module.

    The name is bound into the event dict rather than read off the underlying
    logger: ``PrintLoggerFactory`` writes straight to stdout and has no
    ``.name``, which is what ``structlog.stdlib.add_logger_name`` expects.

    Passing the name as an initial value keeps the returned proxy *lazy*.
    Modules call this at import time, before ``configure_logging`` has run;
    calling ``.bind()`` here instead would materialise the logger against
    structlog's default configuration and silently ignore ``log_format`` and
    ``log_level`` for the rest of the process.

    The key is ``logger_name`` rather than ``logger``: the latter collides with
    ``structlog.wrap_logger``'s own first parameter when the proxy materialises.
    """
    logger: FilteringBoundLogger = structlog.get_logger(logger_name=name)
    return logger
