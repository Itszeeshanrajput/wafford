"""Tests for logging setup."""

import logging
import tempfile
from pathlib import Path


def test_setup_logging():
    """Test logging setup."""
    from wafford.logging.setup import setup_logging
    
    setup_logging(level="DEBUG", log_format="detailed", log_to_console=True, log_to_file=False)
    logger = logging.getLogger("test")
    logger.debug("Test debug message")
    assert logger.level == logging.DEBUG or logger.parent.level == logging.DEBUG


def test_json_formatter():
    """Test JSON formatter."""
    from wafford.logging.setup import JSONFormatter
    
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="Test message",
        args=(),
        exc_info=None,
    )
    formatted = formatter.format(record)
    assert "Test message" in formatted
    assert "INFO" in formatted
