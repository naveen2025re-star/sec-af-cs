"""Compliance-focused report generation.

Generates structured compliance reports with evidence sections,
finding details, and remediation timelines per framework.
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..schemas.compliance import ComplianceGap
    from ..schemas.output import SecurityAuditResult
    from ..schemas.prove import VerifiedFinding


def _normalize_framework(framework: str) -> str:
    return framework.strip().lower().replace("_", "-")


def _framework_filter(framework: str | None) -> str | None:
    if framework is None:
        return None
    normalized = framework.strip()
    if not normalized:
        return None
    return normalized


def _match_framework(framework: str, selected_framework: str | None) -> bool:
    if selected_framework is None:
        return True
    return _normalize_framework(framework) == _normalize_framework(selected_framework)


def _findings_for_framework(result: SecurityAuditResult, framework: str | None) -> list[VerifiedFinding]:
    if framework is None:
        return list(result.findings)
    selected: list[VerifiedFinding] = []
    for finding in result.findings:
        if any(_match_framework(mapping.framework, framework) for mapping in finding.compliance):
            selected.append(finding)
    return selected


def _gaps_for_framework(result: SecurityAuditResult, framework: str | None) -> list[ComplianceGap]:
    if framework is None:
        return list(result.compliance_gaps)
    return [gap for gap in result.compliance_gaps if _match_framework(gap.framework, framework)]


def _severity_distribution(findings: list[VerifiedFinding]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        key = finding.severity.value.lower()
        counts[key] = counts.get(key, 0) + 1
    return counts


def _evidence_level_distribution(findings: list[VerifiedFinding]) -> dict[int, int]:
    levels: dict[int, int] = {1: 0, 2: 0, 3: 0}
    for finding in findings:
        level = int(finding.evidence_level)
        levels[level] = levels.get(level, 0) + 1
    return levels


def _group_findings_by_framework(
    findings: list[VerifiedFinding], framework: str | None
) -> dict[str, dict[str, list[VerifiedFinding]]]:
    grouped: dict[str, dict[str, list[VerifiedFinding]]] = {}
    for finding in findings:
        for mapping in finding.compliance:
            if not _match_framework(mapping.framework, framework):
                continue
            framework_bucket = grouped.setdefault(mapping.framework, {})
            control_key = f"{mapping.control_id} - {mapping.control_name}"
            framework_bucket.setdefault(control_key, []).append(finding)
    return grouped


def _render_remediation_timeline(findings: list[VerifiedFinding]) -> list[str]:
    timeline: dict[str, list[VerifiedFinding]] = {
        "Immediate (0-7 days)": [],
        "Short-term (8-30 days)": [],
        "Mid-term (31-90 days)": [],
        "Long-term (90+ days)": [],
    }
    for finding in findings:
        severity = finding.severity.value.lower()
        if severity == "critical":
            timeline["Immediate (0-7 days)"].append(finding)
        elif severity == "high":
            timeline["Short-term (8-30 days)"].append(finding)
        elif severity == "medium":
            timeline["Mid-term (31-90 days)"].append(finding)
        else:
            timeline["Long-term (90+ days)"].append(finding)

    lines: list[str] = []
    for window, window_findings in timeline.items():
        lines.append(f"### {window}")
        lines.append("")
        if not window_findings:
            lines.append("- No findings currently assigned.")
            lines.append("")
            continue
        lines.append(f"- Findings: {len(window_findings)}")
        top_findings = sorted(window_findings, key=lambda item: item.exploitability_score, reverse=True)[:5]
        for finding in top_findings:
            lines.append(
                f"  - `{finding.id}` {finding.title} "
                + f"(severity: {finding.severity.value}, exploitability: {finding.exploitability_score:.1f}/10)"
            )
        lines.append("")
    return lines


def generate_compliance_report(result: SecurityAuditResult, framework: str | None = None) -> str:
    selected_framework = _framework_filter(framework)
    findings = _findings_for_framework(result, selected_framework)
    gaps = _gaps_for_framework(result, selected_framework)
    by_severity = _severity_distribution(findings)
    by_evidence = _evidence_level_distribution(findings)
    grouped = _group_findings_by_framework(findings, selected_framework)

    findings_by_cwe: dict[str, int] = defaultdict(int)
    for finding in findings:
        findings_by_cwe[finding.cwe_id] += 1

    report_title = "SEC-AF Compliance Report"
    if selected_framework:
        report_title = f"SEC-AF Compliance Report - {selected_framework}"

    lines = [
        f"# {report_title}",
        "",
        "## Executive Summary",
        "",
        f"- Repository: `{result.repository}`",
        f"- Commit: `{result.commit_sha}`",
        f"- Branch: `{result.branch}`" if result.branch else "- Branch: n/a",
        f"- Generated: `{result.timestamp.isoformat()}`",
        f"- Scope: `{selected_framework or 'all frameworks'}`",
        f"- Findings in scope: **{len(findings)}**",
        f"- Compliance gaps in scope: **{len(gaps)}**",
        (
            "- Severity distribution: "
            + f"critical={by_severity['critical']}, high={by_severity['high']}, "
            + f"medium={by_severity['medium']}, low={by_severity['low']}, info={by_severity['info']}"
        ),
        "",
        "## Compliance Framework Coverage",
        "",
    ]

    if grouped:
        for framework_name in sorted(grouped):
            controls = grouped[framework_name]
            mapped_findings = sum(len(items) for items in controls.values())
            lines.append(f"### {framework_name}")
            lines.append("")
            lines.append(f"- Impacted controls: **{len(controls)}**")
            lines.append(f"- Findings mapped to controls: **{mapped_findings}**")
            lines.append("- Controls:")
            for control_name in sorted(controls):
                lines.append(f"  - {control_name} ({len(controls[control_name])} findings)")
            lines.append("")
    else:
        lines.extend(["No framework mappings found for the current scope.", ""])

    lines.extend(["## Finding Details per Framework", ""])
    if grouped:
        for framework_name in sorted(grouped):
            lines.append(f"### {framework_name}")
            lines.append("")
            for control_name in sorted(grouped[framework_name]):
                lines.append(f"#### {control_name}")
                lines.append("")
                for finding in grouped[framework_name][control_name]:
                    lines.extend(
                        [
                            f"- **{finding.title}** (`{finding.id}`)",
                            f"  - Severity: `{finding.severity.value}` | Verdict: `{finding.verdict.value}` | Evidence level: `{int(finding.evidence_level)}`",
                            f"  - CWE: `{finding.cwe_id}` ({finding.cwe_name})",
                            f"  - Location: `{finding.location.file_path}:{finding.location.start_line}`",
                            f"  - Exploitability score: **{finding.exploitability_score:.1f}/10**",
                            f"  - Rationale: {finding.rationale}",
                        ]
                    )
                    if finding.proof and finding.proof.exploit_hypothesis:
                        lines.append(f"  - Exploit hypothesis: {finding.proof.exploit_hypothesis}")
                    if finding.proof and finding.proof.verification_method:
                        lines.append(f"  - Verification method: {finding.proof.verification_method}")
                    if finding.proof and finding.proof.data_flow_trace:
                        lines.append(f"  - Data flow evidence steps: {len(finding.proof.data_flow_trace)}")
                    lines.append("")
    else:
        lines.extend(["No finding details available for the selected framework scope.", ""])

    lines.extend(["## Compliance Gaps", ""])
    if gaps:
        high_priority_gaps = [gap for gap in gaps if gap.max_severity.lower() in {"critical", "high"}]
        lines.append(f"- Total controls with open gaps: **{len(gaps)}**")
        lines.append(f"- High-priority gaps (critical/high): **{len(high_priority_gaps)}**")
        lines.append(f"- Unique impacted CWEs: **{len(findings_by_cwe)}**")
        lines.append("")
        lines.append("| Framework | Control | Finding Count | Max Severity | CWEs |")
        lines.append("| --- | --- | ---: | --- | --- |")
        for gap in sorted(gaps, key=lambda item: (item.framework, item.control_id)):
            cwes = ", ".join(gap.cwe_ids)
            lines.append(
                f"| {gap.framework} | {gap.control_id} - {gap.control_name} | {gap.finding_count} | {gap.max_severity} | {cwes} |"
            )
        lines.append("")
    else:
        lines.extend(["No compliance gaps identified in the selected scope.", ""])

    lines.extend(["## Remediation Timeline", ""])
    lines.extend(_render_remediation_timeline(findings))

    lines.extend(
        [
            "## Evidence Summary",
            "",
            f"- Evidence level 1 findings: **{by_evidence.get(1, 0)}**",
            f"- Evidence level 2 findings: **{by_evidence.get(2, 0)}**",
            f"- Evidence level 3 findings: **{by_evidence.get(3, 0)}**",
        ]
    )

    findings_with_repro = sum(1 for finding in findings if finding.reproduction_steps)
    findings_with_http = sum(
        1
        for finding in findings
        if finding.proof and (finding.proof.http_request is not None or finding.proof.http_response is not None)
    )
    findings_with_data_flow = sum(1 for finding in findings if finding.proof and finding.proof.data_flow_trace)
    lines.extend(
        [
            f"- Findings with reproduction steps: **{findings_with_repro}**",
            f"- Findings with HTTP evidence: **{findings_with_http}**",
            f"- Findings with data-flow traces: **{findings_with_data_flow}**",
            "",
            "This markdown report is designed for downstream PDF conversion workflows.",
        ]
    )

    return "\n".join(lines)
