"""
Final Reporter (Node 17)

Compiles all confirmed findings, severity scores, and non-destructive
proof-of-concepts into a structured JSON report. Also exports the
cryptographic WARC audit log path.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from typing import Any

import structlog

from src.state import ApexState

logger = structlog.get_logger("apexhunter.reporting.reporter")


class ReportGenerator:
    """
    Generates the final vulnerability assessment report in JSON format.

    The report includes:
    - Executive summary (counts by severity)
    - Detailed findings with proof-of-concept
    - Remediation advice per finding
    - Scan metadata (duration, tools used, scope)
    - WARC audit log reference
    """

    def __init__(self, output_dir: str = "/app/output"):
        self._output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def run(self, state: ApexState) -> dict:
        """Generate the final report."""
        vulnerabilities = state.get("vulnerability_report", [])
        scan_id = state.get("scan_id", "unknown")
        target_url = state.get("target_url", "")
        scan_start = state.get("scan_start_time", 0)
        scan_duration = time.time() - scan_start if scan_start else 0
        tech = state.get("technology_fingerprint", {})
        waf = state.get("waf_profile", {})
        endpoints_count = len(state.get("discovered_endpoints", []))
        reduced_count = len(state.get("reduced_attack_surface", []))
        tasks_count = len(state.get("task_tree", []))
        completed_count = len(state.get("completed_tasks", []))
        installed_tools = state.get("installed_tools", [])
        errors = state.get("errors", [])

        # Severity counts
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in vulnerabilities:
            sev = vuln.get("severity", "medium").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Build the report
        report = {
            "report_metadata": {
                "tool": "ApexHunter DAST Agent v1.0",
                "scan_id": scan_id,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "target_url": target_url,
                "scan_duration_seconds": round(scan_duration, 2),
                "scan_duration_human": self._format_duration(scan_duration),
            },
            "executive_summary": {
                "total_vulnerabilities": len(vulnerabilities),
                "severity_breakdown": severity_counts,
                "risk_rating": self._calculate_risk_rating(severity_counts),
                "endpoints_discovered": endpoints_count,
                "unique_templates": reduced_count,
                "tasks_executed": completed_count,
                "tasks_planned": tasks_count,
            },
            "target_profile": {
                "url": target_url,
                "technology_stack": tech,
                "waf_detected": waf.get("detected", False),
                "waf_name": waf.get("waf_name", ""),
                "scope_regex": state.get("target_scope", ""),
            },
            "findings": [],
            "scan_details": {
                "tools_used": installed_tools,
                "errors_encountered": len(errors),
                "error_details": errors[:10],
            },
            "compliance": {
                "warc_audit_log": f"/app/warc/apex_{scan_id}.warc",
                "hash_chain_log": f"/app/warc/apex_{scan_id}.hashchain",
                "non_destructive": True,
                "scope_enforced": True,
            },
        }

        # Add detailed findings sorted by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: severity_order.get(v.get("severity", "medium"), 3),
        )

        for i, vuln in enumerate(sorted_vulns, 1):
            finding = {
                "id": vuln.get("vuln_id", f"FINDING-{i}"),
                "title": vuln.get("title", ""),
                "severity": vuln.get("severity", "medium"),
                "cvss_score": vuln.get("cvss_score", 0),
                "vulnerability_type": vuln.get("vuln_type", ""),
                "owasp_category": vuln.get("owasp_category", ""),
                "affected_endpoint": vuln.get("affected_endpoint", ""),
                "affected_method": vuln.get("affected_method", ""),
                "affected_parameter": vuln.get("affected_param", ""),
                "evidence": vuln.get("evidence", ""),
                "proof_of_concept": vuln.get("request_sent", ""),
                "remediation": vuln.get("remediation", ""),
                "discovered_at": datetime.fromtimestamp(
                    vuln.get("discovered_at", 0), tz=timezone.utc
                ).isoformat()
                if vuln.get("discovered_at")
                else "",
                "is_second_order": vuln.get("is_second_order", False),
                "validated": vuln.get("validated", False),
            }
            report["findings"].append(finding)

        # Write the report
        report_path = os.path.join(self._output_dir, f"apex_report_{scan_id}.json")
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        logger.info(
            "report_generated",
            path=report_path,
            total_findings=len(vulnerabilities),
            critical=severity_counts["critical"],
            high=severity_counts["high"],
        )

        # Print summary to stdout
        self._print_summary(report)

        return {
            "current_phase": "reporting_complete",
        }

    def _calculate_risk_rating(self, counts: dict) -> str:
        """Calculate overall risk rating based on severity counts."""
        if counts.get("critical", 0) > 0:
            return "CRITICAL"
        if counts.get("high", 0) > 0:
            return "HIGH"
        if counts.get("medium", 0) > 0:
            return "MEDIUM"
        if counts.get("low", 0) > 0:
            return "LOW"
        return "CLEAN"

    def _format_duration(self, seconds: float) -> str:
        """Format seconds into human-readable duration."""
        if seconds < 60:
            return f"{seconds:.0f}s"
        if seconds < 3600:
            return f"{seconds / 60:.1f}m"
        return f"{seconds / 3600:.1f}h"

    def _print_summary(self, report: dict) -> None:
        """Print a formatted summary to stdout."""
        summary = report["executive_summary"]
        meta = report["report_metadata"]
        counts = summary["severity_breakdown"]

        print("\n" + "=" * 60)
        print("  APEXHUNTER - SCAN COMPLETE")
        print("=" * 60)
        print(f"  Target:     {meta['target_url']}")
        print(f"  Scan ID:    {meta['scan_id']}")
        print(f"  Duration:   {meta['scan_duration_human']}")
        print(f"  Endpoints:  {summary['endpoints_discovered']}")
        print(f"  Tasks:      {summary['tasks_executed']}/{summary['tasks_planned']}")
        print("-" * 60)
        print(f"  RISK RATING: {summary['risk_rating']}")
        print(f"  Total Findings: {summary['total_vulnerabilities']}")
        print(f"    Critical: {counts.get('critical', 0)}")
        print(f"    High:     {counts.get('high', 0)}")
        print(f"    Medium:   {counts.get('medium', 0)}")
        print(f"    Low:      {counts.get('low', 0)}")
        print(f"    Info:     {counts.get('info', 0)}")
        print("-" * 60)
        print(f"  Report:     {self._output_dir}/apex_report_{meta['scan_id']}.json")
        print(f"  WARC Log:   {report['compliance']['warc_audit_log']}")
        print("=" * 60 + "\n")
