"""Structured logging configuration."""

from __future__ import annotations

import json

import pytest

from campusid.config import Settings
from campusid.logging import configure_logging, get_logger


@pytest.fixture(autouse=True)
def _restore_json_logging() -> None:
    """Leave the process configured as the rest of the suite expects."""
    configure_logging(Settings(log_format="json"))


def test_json_output_is_parseable(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(Settings(log_format="json", log_level="INFO"))

    get_logger("campusid.test").info("broker.startup", environment="ci")

    record = json.loads(capsys.readouterr().out.strip())
    assert record["event"] == "broker.startup"
    assert record["environment"] == "ci"
    assert record["level"] == "info"
    assert record["logger_name"] == "campusid.test"
    assert record["timestamp"].endswith("Z")


def test_logger_obtained_before_configuration_still_honours_settings(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Modules bind their logger at import time, before create_app configures it.

    A logger materialised eagerly at import would freeze structlog's default
    console renderer and silently ignore log_format for the whole process.
    """
    configure_logging(Settings(log_format="console"))
    logger = get_logger("campusid.test")  # obtained under the wrong config
    capsys.readouterr()

    configure_logging(Settings(log_format="json"))
    logger.info("broker.startup")

    assert json.loads(capsys.readouterr().out.strip())["event"] == "broker.startup"


def test_console_format_is_human_readable(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(Settings(log_format="console", log_level="INFO"))

    get_logger("campusid.test").info("broker.startup")

    out = capsys.readouterr().out
    assert "broker.startup" in out
    with pytest.raises(json.JSONDecodeError):
        json.loads(out)


def test_level_filtering_drops_quieter_events(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(Settings(log_format="json", log_level="WARNING"))

    logger = get_logger("campusid.test")
    logger.info("suppressed")
    logger.warning("emitted")

    lines = [line for line in capsys.readouterr().out.splitlines() if line.strip()]
    assert len(lines) == 1
    assert json.loads(lines[0])["event"] == "emitted"
