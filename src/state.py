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


class AttackSurface(TypedDict, total=False):
    """An interactive element on a page that could be an attack vector."""

    element_type: str  # "input", "textarea", "select", "form", "button", "link", "file_upload", "hidden_field", "contenteditable"
    element_id: str
    element_name: str
    element_class: str
    input_type: str  # For inputs: "text", "password", "email", "hidden", "file", etc.
    form_action: str  # The form's action URL if this element belongs to a form
    form_method: str  # GET/POST
    placeholder: str
    max_length: Optional[int]
    pattern: str  # HTML5 validation pattern
    accepts: str  # For file inputs: accepted MIME types
    autocomplete: str
    is_required: bool
    current_value: str
    aria_label: str
    data_attributes: dict[str, str]  # All data-* attributes
    event_handlers: list[str]  # Inline event handlers (onclick, onsubmit, etc.)
    parent_form_id: str
    xpath: str  # XPath to locate this element


class NetworkCapture(TypedDict, total=False):
    """A captured network request/response for a specific page."""

    url: str
    method: str
    request_headers: dict[str, str]
    request_body: str
    response_status: int
    response_headers: dict[str, str]
    response_body_preview: str  # First 2000 chars
    response_size: int
    content_type: str
    resource_type: (
        str  # "xhr", "fetch", "document", "script", "stylesheet", "image", "websocket", "other"
    )
    timing_ms: float
    is_third_party: bool
    initiator: str  # What triggered this request (script URL or user action)
    direction: str  # "outgoing" (sent by page) or "incoming" (loaded by page)


class PageNode(TypedDict, total=False):
    """A single page in the site tree structure."""

    page_id: str
    url: str
    path: str  # URL path component
    title: str
    depth: int  # Depth in the site tree (0 = root)
    parent_id: Optional[str]  # page_id of parent page
    children_ids: list[str]  # page_ids of child pages
    status_code: int
    content_type: str
    response_headers: dict[str, str]
    discovered_via: str  # "crawl", "link", "form_action", "js_navigation", "osint", "sitemap"


class PageCapture(TypedDict, total=False):
    """Complete DOM and network capture for a single page."""

    page_id: str
    url: str
    captured_at: float

    # DOM Capture
    html_content: str  # Full page HTML source
    css_content: list[dict[str, str]]  # List of {url, content} for each stylesheet
    inline_scripts: list[str]  # Inline <script> contents
    external_scripts: list[dict[str, str]]  # List of {url, content_preview}
    meta_tags: dict[str, str]  # All <meta> tag name/content pairs
    page_title: str

    # Attack Surface Discovery
    attack_surfaces: list[AttackSurface]  # All interactive elements
    forms: list[dict[str, Any]]  # Detailed form structures
    links: list[dict[str, str]]  # All links: {href, text, rel, target}
    iframes: list[dict[str, str]]  # Embedded iframes: {src, sandbox}
    websocket_urls: list[str]  # WebSocket connections detected

    # Network Activity
    network_requests: list[NetworkCapture]  # All requests made by this page

    # DOM Sink Activity
    dom_sinks: list[dict[str, Any]]  # Dangerous DOM operations detected

    # Cookies set/modified by this page
    cookies_set: list[dict[str, Any]]

    # Technology signals from this page
    tech_signals: dict[str, Any]


class PageAnalysis(TypedDict, total=False):
    """AI-generated analysis of a page's security posture."""

    page_id: str
    url: str
    analyzed_at: float

    # AI Assessment
    risk_score: float  # 0.0 - 10.0, AI-assigned
    interest_level: str  # "high", "medium", "low", "skip"
    reasoning: str  # Why the AI scored it this way

    # Identified attack vectors (AI-generated, not hardcoded)
    attack_vectors: list[
        dict[str, Any]
    ]  # Each: {type, target_element, technique, priority, description}

    # Recommended tasks for this page
    recommended_tasks: list[dict[str, Any]]

    # Decision
    should_deep_scan: bool  # AI decides whether to go deeper
    deep_scan_focus: list[str]  # What to focus on if deep scanning

    # Points of interest found after task execution
    points_of_interest: list[dict[str, Any]]


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

    # ── Site Tree & Per-Page Intelligence ─────────
    site_tree: list[PageNode]  # Tree structure of all discovered pages
    page_captures: list[PageCapture]  # DOM + network capture per page
    page_analyses: list[PageAnalysis]  # AI analysis per page
    current_page_index: int  # Which page we're currently analyzing
    pages_completed: list[str]  # page_ids that have been fully processed
    pages_requiring_deep_scan: list[str]  # page_ids flagged for deep analysis
    deep_scan_active: bool  # Whether we're in deep scan mode for current page

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
        site_tree=[],
        page_captures=[],
        page_analyses=[],
        current_page_index=0,
        pages_completed=[],
        pages_requiring_deep_scan=[],
        deep_scan_active=False,
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
