# ruff: noqa: SLF001, S108
"""Tests for report generation and export (HTML, PDF, Markdown, JSON)."""

from __future__ import annotations

from pathlib import Path

import pytest

from wafford.reports.export import ReportExporter
from wafford.reports.generator import ReportData, ReportGenerator


def make_report_data() -> ReportData:
    return ReportData(
        session={"id": 42},
        networks=[
            {"essid": "Home", "bssid": "00:1B:2F:AA:BB:CC", "channel": 6,
             "encryption": "WPA2", "signal": -55},
        ],
        attacks=[
            {"type": "deauth", "target": "00:1B:2F:AA:BB:CC", "success": True, "duration": 5.0},
        ],
        handshakes=[{"essid": "Home", "path": "/tmp/hs.cap"}],
        credentials=[{"bssid": "00:1B:2F:AA:BB:CC", "essid": "Home", "password": "s3cret"}],
        duration=120.0,
        summary="All good",
    )


def test_report_data_to_dict() -> None:
    data = make_report_data()
    d = data.to_dict()
    assert d["session"]["id"] == 42
    assert len(d["networks"]) == 1


def test_generate_session_report() -> None:
    gen = ReportGenerator(Path("/tmp"))
    data = gen.generate_session_report("42")
    assert data.session["id"] == "42"
    assert "hostname" in data.session


def test_generate_network_report() -> None:
    gen = ReportGenerator(Path("/tmp"))
    r = gen.generate_network_report("7")
    assert r["network_id"] == "7"
    assert r["clients"] == []


def test_generate_attack_report() -> None:
    gen = ReportGenerator(Path("/tmp"))
    r = gen.generate_attack_report("9")
    assert r["attack_id"] == "9"
    assert r["success"] is False


def test_build_html(tmp_path) -> None:
    gen = ReportGenerator(tmp_path)
    html = gen.build_html(make_report_data())
    assert "<html" in html or "<!DOCTYPE" in html
    assert "Home" in html


def test_build_json(tmp_path) -> None:
    gen = ReportGenerator(tmp_path)
    import json

    data = json.loads(gen.build_json(make_report_data()))
    assert data["session"]["id"] == 42
    assert "statistics" in data
    assert data["statistics"]["networks_discovered"] == 1


def test_build_markdown(tmp_path) -> None:
    gen = ReportGenerator(tmp_path)
    md = gen.build_markdown(make_report_data())
    assert "# Wafford Audit Report" in md
    assert "## Networks Found" in md
    assert "## Attacks Performed" in md
    assert "## Credentials Captured" in md
    assert "Home" in md


def test_build_markdown_empty_still_has_title(tmp_path) -> None:
    gen = ReportGenerator(tmp_path)
    md = gen.build_markdown(ReportData())
    assert "# Wafford Audit Report" in md


def test_build_pdf_falls_back_or_bytes(tmp_path) -> None:
    gen = ReportGenerator(tmp_path)
    result = gen.build_pdf(make_report_data())
    # Either real PDF bytes, or HTML fallback string when weasyprint missing.
    assert isinstance(result, (bytes, str))
    if isinstance(result, bytes):
        assert b"%PDF" in result[:8] or len(result) > 0


def test_format_duration() -> None:
    f = ReportGenerator._format_duration
    assert f(0) == "0s"
    assert f(5.0) == "5.0s"
    assert f(90.0) == "1m 30.0s"
    assert f(3661.0) == "1h 1m 1.0s"


def test_compute_statistics() -> None:
    gen = ReportGenerator(Path("/tmp"))
    stats = gen._compute_statistics(make_report_data())
    assert stats["networks_discovered"] == 1
    assert stats["total_attacks"] == 1
    assert stats["successful_attacks"] == 1
    assert stats["success_rate"] == "100.0%"


def test_compute_statistics_empty() -> None:
    gen = ReportGenerator(Path("/tmp"))
    stats = gen._compute_statistics(ReportData())
    assert stats["success_rate"] == "N/A"


# ── Exporters ───────────────────────────────────────────────────────────────

def test_export_html(tmp_path) -> None:
    exporter = ReportExporter(tmp_path)
    out = exporter.export_html(make_report_data(), tmp_path / "r.html")
    assert out.exists()
    assert "Home" in out.read_text(encoding="utf-8")


def test_export_json(tmp_path) -> None:
    exporter = ReportExporter(tmp_path)
    out = exporter.export_json(make_report_data(), tmp_path / "r.json")
    import json

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["session"]["id"] == 42


def test_export_markdown(tmp_path) -> None:
    exporter = ReportExporter(tmp_path)
    out = exporter.export_markdown(make_report_data(), tmp_path / "r.md")
    text = out.read_text(encoding="utf-8")
    assert "# Wafford Audit Report" in text


def test_export_generic(tmp_path) -> None:
    exporter = ReportExporter(tmp_path)
    out = exporter.export(make_report_data(), fmt="json", output_path=tmp_path / "g.json")
    assert out.suffix == ".json"


def test_export_unsupported_format(tmp_path) -> None:
    exporter = ReportExporter(tmp_path)
    with pytest.raises(ValueError, match="[Uu]nsupported"):
        exporter.export(make_report_data(), fmt="bogus")


def test_export_pdf_fallback(tmp_path) -> None:
    exporter = ReportExporter(tmp_path)
    try:
        import weasyprint  # noqa: F401

        pytest.skip("weasyprint installed; fallback path not exercisable")
    except ImportError:
        pass
    out = exporter.export_pdf(make_report_data(), tmp_path / "r.pdf")
    # Falls back to exporting HTML even though the name asked for pdf.
    assert out.exists()


def test_open_report_missing_returns_false() -> None:
    assert ReportExporter.open_report("/nonexistent/report.html") is False


def test_share_report_file(tmp_path) -> None:
    src = tmp_path / "report.md"
    src.write_text("# report", encoding="utf-8")
    exporter = ReportExporter(tmp_path)
    assert exporter.share_report(src, method="unknown") is False
    assert exporter.share_report(tmp_path / "missing.md", method="file") is False


def test_list_reports(tmp_path) -> None:
    exporter = ReportExporter(tmp_path)
    exporter.export_html(make_report_data(), tmp_path / "a.html")
    exporter.export_json(make_report_data(), tmp_path / "b.json")
    reports = exporter.list_reports()
    assert len(reports) == 2
    assert {r["format"] for r in reports} == {"html", "json"}


def test_delete_report(tmp_path) -> None:
    exporter = ReportExporter(tmp_path)
    p = tmp_path / "d.html"
    p.write_text("x", encoding="utf-8")
    assert exporter.delete_report(p) is True
    assert not p.exists()
    assert exporter.delete_report(p) is False


def test_resolve_output_creates_parent(tmp_path) -> None:
    exporter = ReportExporter(tmp_path)
    dest = tmp_path / "nested" / "out.html"
    resolved = exporter._resolve_output(dest, "html")
    assert resolved == dest
    assert dest.parent.exists()
