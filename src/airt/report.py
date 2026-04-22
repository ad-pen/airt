from __future__ import annotations

from airt.models import Finding, SessionResult, Status

STATUS_ICON = {
    Status.LIKELY_SUCCESS: "★ LIKELY SUCCESS",
    Status.FLAGS_PRESENT: "! FLAGS PRESENT — REVIEW",
    Status.DEFLECTED: "· DEFLECTED",
    Status.NO_SIGNAL: "· NO SIGNAL",
    Status.ERROR: "× ERROR",
}


def render_session(session: SessionResult) -> str:
    lines: list[str] = []
    lines.append(f"# Attack Run: `{session.payload_id}`")
    lines.append("")
    lines.append(f"- **Session:** `{session.id}`")
    lines.append(f"- **Target:** {session.target_name}")
    lines.append(f"- **Attack class:** {session.attack_class.value}")
    lines.append(f"- **Payload title:** {session.payload_title}")
    lines.append(f"- **Started:** {session.started_at.isoformat()}")
    lines.append(f"- **Ended:** {session.ended_at.isoformat()}")
    lines.append(f"- **Overall status:** {STATUS_ICON.get(session.overall_status, session.overall_status.value)}")
    if session.canary_used:
        lines.append(f"- **Canary:** `{session.canary_used}`")
    lines.append("")
    lines.append("## Transcript")
    lines.append("")
    for t in session.turns:
        lines.append(f"### Turn {t.idx}")
        lines.append("")
        lines.append("**User:**")
        lines.append("")
        lines.append("```")
        lines.append(t.user)
        lines.append("```")
        lines.append("")
        lines.append("**Assistant:**")
        lines.append("")
        lines.append("```")
        lines.append(t.assistant if t.assistant else f"(error: {t.error})")
        lines.append("```")
        lines.append("")
        if t.flags:
            lines.append("**Flags:**")
            lines.append("")
            for f in t.flags:
                ev = f.evidence.replace("\n", " ")
                lines.append(f"- `{f.name}` — {ev}")
            lines.append("")
        lines.append(f"**Status:** {STATUS_ICON.get(t.status, t.status.value)}  ·  {t.latency_ms} ms")
        lines.append("")
    return "\n".join(lines)


def render_finding(finding: Finding, session: SessionResult) -> str:
    lines: list[str] = []
    lines.append(f"# Finding: {finding.title}")
    lines.append("")
    lines.append(f"- **ID:** `{finding.id}`")
    lines.append(f"- **Severity:** {finding.severity.value.upper()}")
    lines.append(f"- **Attack class:** {finding.attack_class.value}")
    lines.append(f"- **Target:** {session.target_name}")
    lines.append(f"- **Created:** {finding.created_at.isoformat()}")
    lines.append("")
    if finding.notes:
        lines.append("## Notes")
        lines.append("")
        lines.append(finding.notes)
        lines.append("")
    lines.append("## Reproduction")
    lines.append("")
    lines.append(f"Payload: `{session.payload_id}`  ·  Session: `{session.id}`")
    lines.append("")
    lines.append("## Evidence")
    lines.append("")
    lines.append(render_session(session))
    return "\n".join(lines)


def render_report(findings_with_sessions: list[tuple[Finding, SessionResult]]) -> str:
    lines: list[str] = []
    lines.append("# AI Red Team Report")
    lines.append("")
    lines.append(f"**Findings:** {len(findings_with_sessions)}")
    lines.append("")
    by_sev: dict[str, int] = {}
    for f, _ in findings_with_sessions:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
    lines.append("## Executive Summary")
    lines.append("")
    if not findings_with_sessions:
        lines.append("_No findings promoted._")
    else:
        for sev in ("critical", "high", "medium", "low", "info"):
            if sev in by_sev:
                lines.append(f"- **{sev.upper()}:** {by_sev[sev]}")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    for f, s in findings_with_sessions:
        lines.append(render_finding(f, s))
        lines.append("")
        lines.append("---")
        lines.append("")
    return "\n".join(lines)
