"""
PDF report generation for airt findings.

Uses fpdf2 to produce a self-contained PDF with a title page,
executive summary, and per-finding detail sections.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fpdf import FPDF

from .models import AttackClass, Finding, Severity, SessionResult, Status

# Severity -> RGB colour
_SEVERITY_COLOURS: dict[Severity, tuple[int, int, int]] = {
    Severity.CRITICAL: (200, 50, 50),
    Severity.HIGH: (230, 130, 50),
    Severity.MEDIUM: (200, 180, 50),
    Severity.LOW: (50, 100, 200),
    Severity.INFO: (150, 150, 150),
}

_STATUS_LABEL: dict[Status, str] = {
    Status.LIKELY_SUCCESS: "LIKELY SUCCESS",
    Status.FLAGS_PRESENT: "FLAGS PRESENT",
    Status.DEFLECTED: "DEFLECTED",
    Status.NO_SIGNAL: "NO SIGNAL",
    Status.ERROR: "ERROR",
}


class ReportPDF(FPDF):
    """PDF report with header / footer branding."""

    def header(self) -> None:
        self.set_font("Helvetica", "B", 10)
        self.cell(0, 8, "airt -- AI Red Team Report", align="R")
        self.ln(10)

    def footer(self) -> None:
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------


def _severity_colour(pdf: FPDF, severity: Severity) -> None:
    """Set the PDF text colour for a severity level."""
    r, g, b = _SEVERITY_COLOURS.get(severity, (0, 0, 0))
    pdf.set_text_color(r, g, b)


def _reset_colour(pdf: FPDF) -> None:
    pdf.set_text_color(0, 0, 0)


def _add_title_page(pdf: ReportPDF, findings: list[Finding]) -> None:
    pdf.add_page()
    pdf.ln(40)
    pdf.set_font("Helvetica", "B", 28)
    pdf.cell(0, 14, "AI Red Team Report", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(8)
    pdf.set_font("Helvetica", "", 12)
    pdf.cell(
        0,
        8,
        datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        align="C",
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.ln(16)

    # Severity breakdown on title page
    by_sev: dict[Severity, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, f"Total findings: {len(findings)}", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        count = by_sev.get(sev, 0)
        if count == 0:
            continue
        _severity_colour(pdf, sev)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(
            0,
            8,
            f"{sev.value.upper()}: {count}",
            align="C",
            new_x="LMARGIN",
            new_y="NEXT",
        )
    _reset_colour(pdf)


def _add_executive_summary(pdf: ReportPDF, findings: list[Finding]) -> None:
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 10, "Executive Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    if not findings:
        pdf.set_font("Helvetica", "I", 11)
        pdf.cell(0, 8, "No findings promoted.", new_x="LMARGIN", new_y="NEXT")
        return

    # Severity table
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(60, 8, "Severity", border=1)
    pdf.cell(30, 8, "Count", border=1, new_x="LMARGIN", new_y="NEXT")

    by_sev: dict[Severity, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    pdf.set_font("Helvetica", "", 11)
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        count = by_sev.get(sev, 0)
        if count == 0:
            continue
        _severity_colour(pdf, sev)
        pdf.cell(60, 8, sev.value.upper(), border=1)
        _reset_colour(pdf)
        pdf.cell(30, 8, str(count), border=1, new_x="LMARGIN", new_y="NEXT")

    pdf.ln(6)

    # Attack class coverage
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 8, "Attack class coverage:", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    classes_seen: set[str] = set()
    for f in findings:
        classes_seen.add(f.attack_class.value)
    for cls in sorted(classes_seen):
        pdf.cell(0, 7, f"  - {cls}", new_x="LMARGIN", new_y="NEXT")


def _safe_text(text: str) -> str:
    """Replace characters that fpdf2 latin-1 encoding cannot handle."""
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _add_finding(
    pdf: ReportPDF,
    finding: Finding,
    session: SessionResult | None,
) -> None:
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", "B", 16)
    pdf.multi_cell(0, 9, _safe_text(finding.title), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    # Severity badge
    _severity_colour(pdf, finding.severity)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, f"Severity: {finding.severity.value.upper()}", new_x="LMARGIN", new_y="NEXT")
    _reset_colour(pdf)

    # Metadata
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 7, f"Attack class: {finding.attack_class.value}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, f"Created: {finding.created_at.isoformat()}", new_x="LMARGIN", new_y="NEXT")

    if finding.notes:
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, "Notes", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 6, _safe_text(finding.notes), new_x="LMARGIN", new_y="NEXT")

    # Transcript
    if session is not None and session.turns:
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(0, 8, "Transcript", new_x="LMARGIN", new_y="NEXT")

        for turn in session.turns:
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 7, f"Turn {turn.idx}", new_x="LMARGIN", new_y="NEXT")

            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(0, 6, "User:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Courier", "", 8)
            pdf.multi_cell(0, 5, _safe_text(turn.user), new_x="LMARGIN", new_y="NEXT")

            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(0, 6, "Assistant:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Courier", "", 8)
            assistant_text = turn.assistant if turn.assistant else f"(error: {turn.error})"
            pdf.multi_cell(0, 5, _safe_text(assistant_text), new_x="LMARGIN", new_y="NEXT")

            if turn.flags:
                pdf.set_font("Helvetica", "I", 8)
                for flag in turn.flags:
                    pdf.cell(
                        0,
                        5,
                        _safe_text(f"  Flag: {flag.name} -- {flag.evidence}"),
                        new_x="LMARGIN",
                        new_y="NEXT",
                    )

            pdf.set_font("Helvetica", "", 8)
            status_label = _STATUS_LABEL.get(turn.status, turn.status.value)
            pdf.cell(
                0,
                5,
                f"Status: {status_label}  |  {turn.latency_ms} ms",
                new_x="LMARGIN",
                new_y="NEXT",
            )
            pdf.ln(3)


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------


def render_pdf_report(
    findings: list[Finding],
    sessions: dict[str, SessionResult],
    output_path: str,
) -> str:
    """Generate a PDF report with all findings.

    Parameters
    ----------
    findings:
        Ordered list of findings to include.
    sessions:
        Mapping of *session_id* -> ``SessionResult`` so that each
        finding can include its full transcript.
    output_path:
        Filesystem path where the PDF is written.

    Returns
    -------
    str
        The *output_path* (echoed back for convenience).
    """
    pdf = ReportPDF()
    pdf.alias_nb_pages()

    # Title page
    _add_title_page(pdf, findings)

    # Executive summary
    _add_executive_summary(pdf, findings)

    # Individual findings
    for finding in findings:
        session = sessions.get(finding.session_id)
        _add_finding(pdf, finding, session)

    pdf.output(output_path)
    return output_path
