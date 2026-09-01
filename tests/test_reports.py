"""Tests for report generation."""

from pathlib import Path
import pytest
import tempfile


def test_json_report_builder():
    """Test JSON report generation."""
    from wafford.reports.builder import JSONReportBuilder
    
    with tempfile.TemporaryDirectory() as tmpdir:
        builder = JSONReportBuilder(output_dir=tmpdir)
        builder.add_data("test_key", "test_value")
        report_path = builder.generate()
        assert report_path.exists()
        assert report_path.suffix == ".json"


def test_html_report_builder():
    """Test HTML report generation."""
    from wafford.reports.builder import HTMLReportBuilder
    
    with tempfile.TemporaryDirectory() as tmpdir:
        builder = HTMLReportBuilder(output_dir=tmpdir)
        builder.add_data("test_key", "test_value")
        report_path = builder.generate()
        assert report_path.exists()
        assert report_path.suffix == ".html"
