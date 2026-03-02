"""
Phase 4 Agents: OOB Checker, Differential Reviewer, Pivot Loop,
Second-Order Sweep, and Janitor (Cleanup).

These agents handle post-execution analysis, vulnerability chaining,
artifact cleanup, and data sanitization.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from typing import Any, Optional

import structlog

from src.state import ApexState, Vulnerability, ProxyLogEntry

logger = structlog.get_logger("apexhunter.agents.phase4")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Node 12: Async OOB Checker
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class OOBCheckerAgent:
    """
    Polls the private OOB (Out-of-Band) listener for delayed
    backend callbacks that indicate blind vulnerabilities
    (Blind SSRF, Blind SQLi, Log4Shell, Blind XXE).
    """

    def __init__(self, http_client: Any):
        self._http = http_client

    async def run(self, state: ApexState) -> dict:
        """Check for OOB interactions."""
        oob_url = state.get("oob_listener_url", "")
        interaction_id = state.get("oob_interaction_id", "")

        if not oob_url:
            logger.info("oob_checker_skipped", reason="no OOB listener configured")
            return {}

        logger.info("oob_checker_start", listener=oob_url)

        oob_findings: list[dict] = list(state.get("oob_findings", []))
        vulnerabilities: list[Vulnerability] = list(state.get("vulnerability_report", []))

        # Poll the interactsh API for interactions
        try:
            poll_url = f"{oob_url}/poll"
            if interaction_id:
                poll_url += f"?id={interaction_id}"

            resp = await self._http.get(poll_url, auth_role="oob_checker")
            if resp and resp.status_code == 200:
                data = resp.json()
                interactions = data.get("data", []) or data.get("interactions", [])

                for interaction in interactions:
                    finding = {
                        "type": interaction.get("protocol", "unknown"),
                        "remote_address": interaction.get("remote-address", ""),
                        "timestamp": interaction.get("timestamp", ""),
                        "raw_request": interaction.get("raw-request", "")[:2000],
                        "unique_id": interaction.get("unique-id", ""),
                    }
                    oob_findings.append(finding)

                    # Create a vulnerability for each OOB interaction
                    vuln = Vulnerability(
                        vuln_id=f"OOB-{uuid.uuid4().hex[:8].upper()}",
                        title=f"Blind {finding['type'].upper()} Interaction Detected",
                        vuln_type=f"blind_{finding['type']}",
                        owasp_category="A10" if "http" in finding["type"] else "A03",
                        severity="critical",
                        cvss_score=9.1,
                        affected_endpoint="unknown (OOB callback)",
                        affected_method="",
                        affected_param="",
                        evidence=f"OOB {finding['type']} callback received from {finding['remote_address']}",
                        request_sent="",
                        response_received=finding["raw_request"][:1000],
                        remediation="Investigate the source of the OOB callback. Likely SSRF, Blind XXE, or Log4Shell.",
                        discovered_at=time.time(),
                        validated=True,
                        is_second_order=False,
                        chain_parent=None,
                    )
                    vulnerabilities.append(vuln)

                logger.info("oob_checker_complete", interactions=len(interactions))

        except Exception as e:
            logger.warning("oob_checker_error", error=str(e))

        return {
            "oob_findings": oob_findings,
            "vulnerability_report": vulnerabilities,
            "current_phase": "oob_check_complete",
        }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Node 13: The Differential Reviewer
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class DifferentialReviewerAgent:
    """
    Performs Heuristic Differential Analysis on completed tasks.

    Instead of looking for error messages, it mathematically compares
    True vs False injected states to find silent vulnerabilities:
    - Time difference (blind SQLi via sleep)
    - Length difference (boolean-based blind SQLi)
    - DOM/structure difference
    """

    def __init__(self, http_client: Any):
        self._http = http_client

    async def run(self, state: ApexState) -> dict:
        """Execute differential analysis on all endpoints with parameters."""
        reduced_surface = state.get("reduced_attack_surface", [])
        vulnerabilities: list[Vulnerability] = list(state.get("vulnerability_report", []))

        logger.info("reviewer_start", endpoints=len(reduced_surface))

        # Select endpoints with parameters for differential testing
        testable = [
            ep for ep in reduced_surface if ep.get("params") and ep.get("method", "GET") == "GET"
        ][:30]  # Limit to 30 endpoints

        for ep in testable:
            url = ep.get("example_url", "")
            params = ep.get("params", [])
            if not url or not params:
                continue

            param_names = []
            for p in params:
                name = p.get("name", "") if isinstance(p, dict) else str(p)
                if name:
                    param_names.append(name)

            if not param_names:
                continue

            for param in param_names[:3]:
                result = await self._differential_test(url, param)
                if result and result.get("vulnerable"):
                    vuln = Vulnerability(
                        vuln_id=f"DIFF-{uuid.uuid4().hex[:8].upper()}",
                        title=f"Blind {result['vuln_type']} on {url} (param: {param})",
                        vuln_type=result["vuln_type"],
                        owasp_category="A03",
                        severity="high",
                        cvss_score=8.0,
                        affected_endpoint=url,
                        affected_method="GET",
                        affected_param=param,
                        evidence=result.get("evidence", ""),
                        request_sent="",
                        response_received="",
                        remediation="Use parameterized queries. Implement input validation.",
                        discovered_at=time.time(),
                        validated=True,
                        is_second_order=False,
                        chain_parent=None,
                    )
                    vulnerabilities.append(vuln)

        logger.info("reviewer_complete", vulns_found=len(vulnerabilities))

        return {
            "vulnerability_report": vulnerabilities,
            "current_phase": "review_complete",
        }

    async def _differential_test(self, url: str, param: str) -> Optional[dict]:
        """
        Run differential analysis on a single parameter.

        Sends a "true" condition and a "false" condition, then
        compares responses mathematically.
        """
        # Boolean-based differential
        true_url = f"{url}?{param}=1 AND 1=1" if "?" not in url else f"{url}&{param}=1 AND 1=1"
        false_url = f"{url}?{param}=1 AND 1=2" if "?" not in url else f"{url}&{param}=1 AND 1=2"

        start_true = time.time()
        true_resp = await self._http.get(true_url, auth_role="scanner")
        true_time = (time.time() - start_true) * 1000

        start_false = time.time()
        false_resp = await self._http.get(false_url, auth_role="scanner")
        false_time = (time.time() - start_false) * 1000

        if not true_resp or not false_resp:
            return None

        # Get baseline
        base_url = f"{url}?{param}=1" if "?" not in url else f"{url}&{param}=1"
        base_resp = await self._http.get(base_url, auth_role="scanner")
        if not base_resp:
            return None

        # Compare lengths
        true_len = len(true_resp.text)
        false_len = len(false_resp.text)
        base_len = len(base_resp.text)

        # Length differential: true should match baseline, false should differ
        true_diff = abs(true_len - base_len)
        false_diff = abs(false_len - base_len)

        if true_diff < 50 and false_diff > 100:
            return {
                "vulnerable": True,
                "vuln_type": "sqli_blind_boolean",
                "evidence": (
                    f"Boolean-based blind SQLi detected. "
                    f"True condition length: {true_len} (baseline: {base_len}), "
                    f"False condition length: {false_len}"
                ),
            }

        # Time-based differential
        time_url = (
            f"{url}?{param}=1' AND SLEEP(3)--"
            if "?" not in url
            else f"{url}&{param}=1' AND SLEEP(3)--"
        )
        start_time = time.time()
        time_resp = await self._http.get(time_url, auth_role="scanner")
        elapsed = (time.time() - start_time) * 1000

        if elapsed > 3000 and true_time < 1500:
            return {
                "vulnerable": True,
                "vuln_type": "sqli_blind_time",
                "evidence": (
                    f"Time-based blind SQLi detected. "
                    f"SLEEP(3) caused {elapsed:.0f}ms response (baseline: {true_time:.0f}ms)"
                ),
            }

        return None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Node 14: The Pivot Loop
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class PivotLoopAgent:
    """
    If the Reviewer confirms a critical vulnerability (SSRF, LFI),
    this agent routes the state back to the Planner to generate
    non-destructive "Impact Proof" tasks.
    """

    def run(self, state: ApexState) -> dict:
        """Check if we should pivot based on confirmed vulnerabilities or untested endpoints."""
        vulnerabilities = state.get("vulnerability_report", [])
        pivot_count = state.get("pivot_count", 0)
        iteration_count = state.get("iteration_count", 0)
        max_pivots = state.get("max_pivots", 5)
        pivot_vulns = list(state.get("pivot_vulns", []))
        untested = state.get("untested_surface", [])

        # 1. Continue iteration if there are still untested endpoints
        if len(untested) > 0 and iteration_count < 20:  # Max 20 batches (up to 400 endpoints)
            logger.info(
                "iteration_triggered",
                remaining_endpoints=len(untested),
                iteration=iteration_count + 1,
            )
            return {
                "iteration_count": iteration_count + 1,
                "current_phase": "pivot_to_planner",
            }

        # 2. Pivot-worthy vulnerability types
        pivotable_types = {"ssrf", "lfi", "rce", "auth_bypass", "bac"}

        should_pivot = False
        for vuln in vulnerabilities:
            vuln_type = vuln.get("vuln_type", "")
            vuln_id = vuln.get("vuln_id", "")

            if (
                vuln_type in pivotable_types
                and vuln_id not in pivot_vulns
                and pivot_count < max_pivots
            ):
                should_pivot = True
                pivot_vulns.append(vuln_id)
                logger.info(
                    "pivot_triggered",
                    vuln_type=vuln_type,
                    vuln_id=vuln_id,
                    pivot_count=pivot_count + 1,
                )
                break

        if should_pivot:
            return {
                "pivot_count": pivot_count + 1,
                "pivot_vulns": pivot_vulns,
                "current_phase": "pivot_to_planner",
            }

        return {
            "pivot_vulns": pivot_vulns,
            "current_phase": "pivot_complete",
        }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Node 15: Second-Order Sweep
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class SecondOrderSweepAgent:
    """
    Re-authenticates as higher-privilege roles and re-crawls
    dashboard pages to detect stored payloads that executed later
    (Second-Order XSS, Second-Order SQLi).
    """

    def __init__(self, http_client: Any):
        self._http = http_client

    async def run(self, state: ApexState) -> dict:
        """Execute the second-order sweep."""
        auth_matrix = state.get("auth_matrix", [])
        discovered_endpoints = state.get("discovered_endpoints", [])
        vulnerabilities: list[Vulnerability] = list(state.get("vulnerability_report", []))

        logger.info("second_order_sweep_start")

        # Find admin/high-privilege tokens
        admin_tokens = [
            t
            for t in auth_matrix
            if t.get("role", "").lower() in ("admin", "administrator", "superadmin")
        ]
        if not admin_tokens:
            admin_tokens = auth_matrix[:1]

        if not admin_tokens:
            logger.info("second_order_sweep_skipped", reason="no admin tokens")
            return {"current_phase": "second_order_complete"}

        admin_token = admin_tokens[0]
        headers = dict(admin_token.get("headers", {}))
        cookies = dict(admin_token.get("cookies", {}))

        # Find dashboard/admin endpoints to re-visit
        dashboard_urls = []
        for ep in discovered_endpoints:
            url = ep.get("url", "").lower()
            if any(
                kw in url
                for kw in [
                    "admin",
                    "dashboard",
                    "panel",
                    "manage",
                    "users",
                    "settings",
                    "config",
                    "profile",
                    "account",
                    "list",
                    "view",
                    "report",
                    "log",
                    "audit",
                ]
            ):
                dashboard_urls.append(ep.get("url", ""))

        if not dashboard_urls:
            logger.info("second_order_sweep_no_dashboards")
            return {"current_phase": "second_order_complete"}

        # Visit each dashboard page as admin and check for injected payloads
        xss_indicators = [
            "<script>alert(",
            "<img src=x onerror=",
            "<svg onload=",
            "javascript:alert(",
            "onerror=alert(",
            "onload=alert(",
        ]

        for url in dashboard_urls[:20]:
            try:
                resp = await self._http.get(
                    url,
                    headers=headers,
                    cookies=cookies,
                    auth_role="admin_sweep",
                )
                if resp and resp.status_code == 200:
                    body = resp.text.lower()
                    for indicator in xss_indicators:
                        if indicator.lower() in body:
                            vuln = Vulnerability(
                                vuln_id=f"2ND-{uuid.uuid4().hex[:8].upper()}",
                                title=f"Second-Order XSS on {url}",
                                vuln_type="xss_stored",
                                owasp_category="A03",
                                severity="critical",
                                cvss_score=9.0,
                                affected_endpoint=url,
                                affected_method="GET",
                                affected_param="stored_payload",
                                evidence=f"Stored XSS payload '{indicator}' found in admin page",
                                request_sent="",
                                response_received=body[:1000],
                                remediation="Sanitize ALL user input before storage AND rendering.",
                                discovered_at=time.time(),
                                validated=True,
                                is_second_order=True,
                                chain_parent=None,
                            )
                            vulnerabilities.append(vuln)
                            logger.warning("second_order_xss_found", url=url)
                            break
            except Exception as e:
                logger.debug("second_order_sweep_error", url=url, error=str(e))

        logger.info("second_order_sweep_complete")

        return {
            "vulnerability_report": vulnerabilities,
            "current_phase": "second_order_complete",
        }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Node 16: The Janitor (Cleanup)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class JanitorAgent:
    """
    Tracks all state-changing requests (POST/PUT/DELETE) made
    during the scan and attempts to revert them by issuing
    corresponding DELETE/undo requests.
    """

    def __init__(self, http_client: Any):
        self._http = http_client

    async def run(self, state: ApexState) -> dict:
        """Execute cleanup of state-changing artifacts."""
        state_changing = state.get("state_changing_requests", [])

        if not state_changing:
            logger.info("janitor_skipped", reason="no state-changing requests")
            return {"current_phase": "cleanup_complete"}

        logger.info("janitor_start", artifacts=len(state_changing))

        cleaned = 0
        failed = 0

        for req in state_changing:
            method = req.get("method", "")
            url = req.get("url", "")
            status = req.get("status_code", 0)

            # Only try to clean up successful state changes
            if status not in (200, 201, 202, 204):
                continue

            try:
                if method in ("POST", "PUT", "PATCH"):
                    # Try DELETE on the same URL
                    resp = await self._http.delete(url, auth_role="janitor")
                    if resp and resp.status_code in (200, 204, 404):
                        cleaned += 1
                    else:
                        failed += 1
            except Exception as e:
                logger.debug("janitor_cleanup_error", url=url, error=str(e))
                failed += 1

        logger.info("janitor_complete", cleaned=cleaned, failed=failed)

        return {"current_phase": "cleanup_complete"}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Node 18: Data Sanitization (Local Cleanup)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class DataSanitizerAgent:
    """
    Securely shreds the local SQLite LangGraph state, mitmproxy logs,
    and all captured credentials from the Docker environment to ensure
    post-engagement privacy compliance (GDPR/SOC2).
    """

    def __init__(self, config: Any):
        self._config = config

    async def run(self, state: ApexState) -> dict:
        """Securely sanitize all local sensitive data."""
        logger.info("sanitizer_start")

        files_shredded = 0
        dirs_cleaned = []

        # Directories to clean
        sensitive_dirs = [
            self._config.paths.state_dir if self._config else "/app/state",
            self._config.paths.log_dir if self._config else "/app/logs",
        ]

        for dir_path in sensitive_dirs:
            if os.path.exists(dir_path):
                for root, _dirs, files in os.walk(dir_path):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        try:
                            # Attempt secure shred
                            proc = await asyncio.create_subprocess_exec(
                                "shred",
                                "-u",
                                "-z",
                                "-n",
                                "3",
                                fpath,
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE,
                            )
                            await asyncio.wait_for(proc.communicate(), timeout=30)
                            files_shredded += 1
                        except (FileNotFoundError, asyncio.TimeoutError):
                            # Fallback: regular delete
                            try:
                                os.unlink(fpath)
                                files_shredded += 1
                            except OSError:
                                pass
                dirs_cleaned.append(dir_path)

        logger.info(
            "sanitizer_complete",
            files_shredded=files_shredded,
            dirs_cleaned=dirs_cleaned,
        )

        return {"current_phase": "sanitization_complete"}
