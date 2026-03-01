"""
ApexHunter LangGraph State Definition

This is the central "Memory Matrix" — the TypedDict that flows
through every node in the LangGraph state machine. Every piece of
intelligence gathered, every task planned, and every vulnerability
found is stored here and checkpointed for crash recovery.
"""

from __future__ import annotations

import time
from typing import Any, Optional
from typing_extensions import TypedDict


class Endpoint(TypedDict, total=False):
    """A discovered API endpoint."""

    url: str
    method: str
    params: list[dict[str, Any]]
    headers: dict[str, str]
    content_type: str
    requires_auth: bool
    source: str  # "crawl", "openapi", "osint", "fuzz"


class AuthToken(TypedDict, total=False):
    """An authenticated session for a specific role."""

    role: str
    token_type: str  # "cookie", "jwt", "bearer", "session"
    token_value: str
    cookies: dict[str, str]
    headers: dict[str, str]
    expires_at: Optional[float]
    is_valid: bool


class TaskItem(TypedDict, total=False):
    """A single task in the Task Tree."""

    task_id: str
    target_endpoint: str
    target_method: str
    target_params: list[str]
    vuln_type: str  # "sqli", "xss", "idor", "bac", "ssrf", etc.
    owasp_category: str
    recommended_tool: str  # "nuclei", "custom_script", "ffuf", etc.
    payloads: list[str]
    priority: int  # 1=critical, 5=low
    status: str  # "pending", "in_progress", "completed", "skipped"
    result: Optional[dict[str, Any]]


class Vulnerability(TypedDict, total=False):
    """A confirmed vulnerability finding."""

    vuln_id: str
    title: str
    vuln_type: str
    owasp_category: str
    severity: str  # "critical", "high", "medium", "low", "info"
    cvss_score: float
    affected_endpoint: str
    affected_method: str
    affected_param: str
    evidence: str  # The proof-of-concept description
    request_sent: str
    response_received: str
    remediation: str
    discovered_at: float
    validated: bool
    is_second_order: bool
    chain_parent: Optional[str]  # Links to parent vuln for pivot chains


class HealthMetrics(TypedDict, total=False):
    """Real-time health monitoring data."""

    total_requests: int
    total_5xx_errors: int
    total_4xx_errors: int
    error_rate_percent: float
    avg_response_time_ms: float
    last_check_time: float
    circuit_breaker_tripped: bool
    is_sleeping: bool
    sleep_until: Optional[float]
    speed_factor: float  # 1.0 = full speed, 0.5 = half speed


class WAFProfile(TypedDict, total=False):
    """Detected WAF characteristics."""

    detected: bool
    waf_name: str  # "cloudflare", "aws_waf", "akamai", etc.
    block_status_code: int
    block_indicators: list[str]  # Strings in blocked responses
    evasion_techniques: list[str]
    safe_request_rate: float  # Requests per second


class ProxyLogEntry(TypedDict, total=False):
    """A single captured request/response from the internal proxy."""

    timestamp: float
    method: str
    url: str
    request_headers: dict[str, str]
    request_body: str
    status_code: int
    response_headers: dict[str, str]
    response_body: str
    response_time_ms: float
    auth_role: str  # Which role's token was used


class ApexState(TypedDict, total=False):
    """
    The master LangGraph state object.

    This is checkpointed after every node transition.
    If the agent crashes, it resumes from the last checkpoint.
    """

    # ── Target & Scope ────────────────────────────
    target_url: str
    target_scope: str  # Regex for the RoE Gatekeeper

    # ── Authentication ────────────────────────────
    auth_matrix: list[AuthToken]
    auth_credentials: list[dict[str, str]]

    # ── Reconnaissance Data ───────────────────────
    discovered_endpoints: list[Endpoint]
    openapi_schemas: list[dict[str, Any]]
    historical_osint_data: list[dict[str, Any]]
    hidden_surface_map: list[Endpoint]
    technology_fingerprint: dict[str, Any]
    dom_sink_logs: list[dict[str, Any]]

    # ── WAF ───────────────────────────────────────
    waf_profile: WAFProfile

    # ── Planning ──────────────────────────────────
    reduced_attack_surface: list[dict[str, Any]]
    untested_surface: list[dict[str, Any]]
    task_tree: list[TaskItem]
    rag_context: list[dict[str, Any]]

    # ── Execution Tracking ────────────────────────
    completed_tasks: list[TaskItem]
    proxy_logs: list[ProxyLogEntry]
    state_changing_requests: list[ProxyLogEntry]

    # ── OOB ───────────────────────────────────────
    oob_listener_url: str
    oob_interaction_id: str
    oob_findings: list[dict[str, Any]]

    # ── Findings ──────────────────────────────────
    vulnerability_report: list[Vulnerability]

    # ── Health & Guardrails ───────────────────────
    health_metrics: HealthMetrics

    # ── Installed Tools ───────────────────────────
    installed_tools: list[str]

    # ── Pivot Loop ────────────────────────────────
    iteration_count: int
    pivot_count: int
    max_pivots: int
    pivot_vulns: list[str]  # vuln_ids that triggered pivots

    # ── Metadata ──────────────────────────────────
    scan_id: str
    scan_start_time: float
    current_phase: str
    errors: list[dict[str, Any]]


def create_initial_state(
    target_url: str,
    target_scope: str,
    credentials: list[dict[str, str]],
    scan_id: str,
) -> ApexState:
    """Create the initial state for a new scan."""
    return ApexState(
        target_url=target_url,
        target_scope=target_scope,
        auth_matrix=[],
        auth_credentials=credentials,
        discovered_endpoints=[],
        openapi_schemas=[],
        historical_osint_data=[],
        hidden_surface_map=[],
        technology_fingerprint={},
        dom_sink_logs=[],
        waf_profile=WAFProfile(
            detected=False,
            waf_name="",
            block_status_code=0,
            block_indicators=[],
            evasion_techniques=[],
            safe_request_rate=10.0,
        ),
        reduced_attack_surface=[],
        untested_surface=[],
        task_tree=[],
        rag_context=[],
        completed_tasks=[],
        proxy_logs=[],
        state_changing_requests=[],
        oob_listener_url="",
        oob_interaction_id="",
        oob_findings=[],
        vulnerability_report=[],
        health_metrics=HealthMetrics(
            total_requests=0,
            total_5xx_errors=0,
            total_4xx_errors=0,
            error_rate_percent=0.0,
            avg_response_time_ms=0.0,
            last_check_time=time.time(),
            circuit_breaker_tripped=False,
            is_sleeping=False,
            sleep_until=None,
            speed_factor=1.0,
        ),
        installed_tools=[],
        iteration_count=0,
        pivot_count=0,
        max_pivots=3,
        pivot_vulns=[],
        scan_id=scan_id,
        scan_start_time=time.time(),
        current_phase="initialization",
        errors=[],
    )
