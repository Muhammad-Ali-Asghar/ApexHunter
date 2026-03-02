"""
Threat & Logic Planner (Node 8 - Cloud LLM)

Analyzes the per-page analysis data (attack vectors, recommended tasks,
attack surfaces, network requests) and uses a Cloud LLM to generate
a comprehensive Task Tree for the CURRENT page.

This planner operates in two modes:
  1. PAGE MODE: Generate tasks for the current page based on PageAnalysis
  2. GLOBAL MODE: Generate tasks from the legacy reduced_attack_surface
     (backwards compatible, used when page analyses aren't available)

All detection patterns, severity scoring, and task generation are
AI-driven — nothing is hardcoded.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

import structlog

from src.state import ApexState, TaskItem

logger = structlog.get_logger("apexhunter.agents.planner")

PLANNER_SYSTEM_PROMPT = """You are an expert penetration tester with 20 years of experience.
You are analyzing a web page's security data to create a comprehensive,
non-destructive vulnerability testing plan.

You have been given:
- The AI-generated security analysis for this page (risk score, identified attack vectors)
- The full attack surface (all interactive elements with their attributes)
- Network requests made by the page
- DOM sink activity
- Technology signals
- Cookie information
- WAF profile

Your task is to generate a prioritized list of security tests (Task Tree).
Each task must be:
1. NON-DESTRUCTIVE — identification only, no exploitation
2. Targeted at a SPECIFIC element, parameter, or endpoint on this page
3. Mapped to an OWASP Top 10 category
4. Assigned a priority (1=critical, 5=low)

For each test, output a JSON object with:
- task_id: unique identifier (e.g., "task-abc123")
- target_endpoint: the URL to test
- target_method: HTTP method (GET, POST, PUT, DELETE, etc.)
- target_params: list of parameter names to inject into
- vuln_type: specific vulnerability type (be precise, e.g., "sqli_error", "xss_reflected", "csrf_missing", "idor", "ssti", "ssrf", "open_redirect", "file_upload_bypass", "jwt_manipulation", "graphql_introspection", "websocket_injection", "http_smuggling", "cache_poisoning", "race_condition", "broken_access_control", "sensitive_data_exposure", "security_header_missing", "cors_misconfiguration", etc.)
- owasp_category: OWASP category code (A01-A10)
- recommended_tool: one of "nuclei", "custom_script", "ffuf", "direct_http"
- payloads: list of specific payload strings to test with (generate appropriate payloads for the vuln type - be creative, don't use generic lists)
- priority: 1-5

CRITICAL RULES:
- Generate payloads dynamically based on the specific context (technology stack, form field types, existing validation patterns)
- If a form has a maxlength attribute, test with payloads that exceed it
- If a hidden field contains what looks like an ID, generate IDOR test payloads
- If DOM sinks are present with URL parameter sources, generate DOM XSS payloads
- If the page has CSRF tokens, test for CSRF bypass techniques
- If file upload is present, generate extension/content-type bypass payloads
- If you see API calls (XHR/fetch), generate injection payloads appropriate for the API
- Consider the WAF profile when generating payloads (use evasion if WAF detected)

Output ONLY a valid JSON array of task objects. No explanation text."""


PLANNER_PAGE_TEMPLATE = """## Current Page
- URL: {page_url}
- Title: {page_title}
- Risk Score: {risk_score}/10
- Interest Level: {interest_level}

## AI Analysis Reasoning
{analysis_reasoning}

## Identified Attack Vectors (from Page Analyzer)
{attack_vectors}

## Recommended Tasks (from Page Analyzer)
{recommended_tasks}

## Attack Surfaces ({surface_count} elements)
{attack_surfaces}

## Forms ({form_count})
{forms}

## Network Requests Summary ({request_count})
{network_requests}

## DOM Sinks ({sink_count})
{dom_sinks}

## Cookies Set ({cookie_count})
{cookies}

## Technology Signals
{tech_signals}

## Context
- Target Base URL: {target_url}
- WAF: {waf_info}
- Auth Roles: {auth_roles}
- Deep Scan Mode: {deep_scan}
- Previously Found Vulnerabilities: {prev_vulns}

Generate a comprehensive Task Tree for non-destructive vulnerability testing of THIS page.
If the page has no meaningful attack surface, return an empty JSON array [].
If in deep scan mode, generate more thorough and creative tests."""


PLANNER_GLOBAL_TEMPLATE = """## Target Information
- URL: {target_url}
- Technologies: {tech_stack}
- WAF Detected: {waf_detected} ({waf_name})

## Reduced Attack Surface ({endpoint_count} unique templates)
{attack_surface}

## DOM Sink Activity
{dom_sinks}

## API Schemas Found
{api_schemas}

## Authentication Matrix
Roles available: {auth_roles}

## Confirmed Vulnerabilities (Pivot Data)
{confirmed_vulns}

Generate a comprehensive Task Tree for non-destructive vulnerability testing.
If the Attack Surface is empty and no vulnerabilities need pivoting, return an empty JSON array []."""


class PlannerAgent:
    """
    The Strategic Planner — uses a Cloud LLM to generate
    a comprehensive, prioritized Task Tree.

    Operates in two modes:
    - Page mode: plans tests for the current page using PageAnalysis data
    - Global mode: legacy mode using reduced_attack_surface
    """

    def __init__(self, llm: Any):
        self._llm = llm

    async def run(self, state: ApexState) -> dict:
        """Execute the planning phase."""
        target_url = state.get("target_url", "")
        if not target_url:
            logger.error("planner_no_target_url")
            return {"task_tree": [], "current_phase": "planning_skipped"}

        # Determine mode: page-by-page or global
        page_analyses = state.get("page_analyses", [])
        current_index = state.get("current_page_index", 0)
        site_tree = state.get("site_tree", [])

        if page_analyses and current_index < len(site_tree):
            # PAGE MODE: Plan for the current page
            return await self._plan_for_page(state)
        else:
            # GLOBAL MODE: Legacy planning from reduced attack surface
            return await self._plan_global(state)

    async def _plan_for_page(self, state: ApexState) -> dict:
        """Generate tasks for the current page using its PageAnalysis."""
        site_tree = state.get("site_tree", [])
        current_index = state.get("current_page_index", 0)
        page_analyses = state.get("page_analyses", [])
        page_captures = state.get("page_captures", [])
        target_url = state.get("target_url", "")

        page_node = site_tree[current_index]
        page_id = page_node.get("page_id", "")
        page_url = page_node.get("url", "")

        # Find the analysis for this page
        analysis = None
        for a in page_analyses:
            if a.get("page_id") == page_id:
                analysis = a
                break

        if not analysis:
            logger.warning("planner_no_analysis_for_page", page_id=page_id)
            return {"task_tree": [], "current_phase": "planning_skipped"}

        # Skip pages the analyzer said to skip
        if analysis.get("interest_level") == "skip":
            logger.info("planner_skipping_page", page_id=page_id, reason="analyzer_skip")
            return {"task_tree": [], "current_phase": "planning_skipped"}

        # Find the capture for this page
        capture = None
        for c in page_captures:
            if c.get("page_id") == page_id:
                capture = c
                break

        # Build the prompt
        user_prompt = self._build_page_prompt(analysis, capture, state)

        logger.info(
            "planner_page_start",
            page_id=page_id,
            url=page_url,
            risk_score=analysis.get("risk_score", 0),
            deep_scan=state.get("deep_scan_active", False),
        )

        try:
            from langchain_core.messages import SystemMessage, HumanMessage

            messages = [
                SystemMessage(content=PLANNER_SYSTEM_PROMPT),
                HumanMessage(content=user_prompt),
            ]

            response = await self._llm.ainvoke(messages)
            response_text = response.content if hasattr(response, "content") else str(response)

            task_tree = self._parse_task_tree(response_text)

            # Deduplicate
            seen = set()
            deduped = []
            for task in task_tree:
                key = f"{task.get('target_endpoint')}:{task.get('vuln_type')}:{','.join(task.get('target_params', []))}"
                if key not in seen:
                    seen.add(key)
                    deduped.append(task)

            logger.info("planner_page_complete", page_id=page_id, tasks=len(deduped))

            return {
                "task_tree": deduped,
                "current_phase": "planning_complete",
            }

        except Exception as e:
            logger.error("planner_llm_error", error=str(e))
            # Fallback: convert analyzer's recommended_tasks to TaskItems
            fallback_tasks = self._convert_analyzer_tasks(analysis, page_url)
            return {
                "task_tree": fallback_tasks,
                "current_phase": "planning_complete",
                "errors": list(state.get("errors", []))
                + [{"phase": "planner", "error": str(e), "time": time.time()}],
            }

    async def _plan_global(self, state: ApexState) -> dict:
        """Legacy global planning from reduced attack surface."""
        target_url = state.get("target_url", "")

        # Take up to 20 untested endpoints for this iteration
        untested = state.get("untested_surface", [])
        batch_size = 20
        batch = untested[:batch_size]
        remaining_untested = untested[batch_size:]

        if not batch and not state.get("vulnerability_report", []):
            logger.info("planner_no_more_endpoints")
            return {"task_tree": [], "current_phase": "planning_skipped"}

        dom_sinks = state.get("dom_sink_logs", [])
        api_schemas = state.get("openapi_schemas", [])
        tech = state.get("technology_fingerprint", {})
        waf = state.get("waf_profile", {})
        auth_matrix = state.get("auth_matrix", [])

        logger.info(
            "planner_global_start", batch_size=len(batch), remaining=len(remaining_untested)
        )

        attack_surface_str = json.dumps(batch, indent=2, default=str)
        dom_sinks_str = (
            json.dumps(dom_sinks[:20], indent=2, default=str) if dom_sinks else "None detected"
        )
        api_schemas_str = (
            json.dumps(
                [{"url": s.get("url"), "type": s.get("type")} for s in api_schemas],
                indent=2,
            )
            if api_schemas
            else "None found"
        )
        auth_roles = (
            ", ".join(t.get("role", "unknown") for t in auth_matrix)
            if auth_matrix
            else "unauthenticated only"
        )

        user_prompt = PLANNER_GLOBAL_TEMPLATE.format(
            target_url=target_url,
            tech_stack=json.dumps(tech, default=str),
            waf_detected=waf.get("detected", False),
            waf_name=waf.get("waf_name", "none"),
            endpoint_count=len(state.get("reduced_attack_surface", [])),
            attack_surface=attack_surface_str[:8000],
            dom_sinks=dom_sinks_str[:2000],
            api_schemas=api_schemas_str[:2000],
            auth_roles=auth_roles,
            confirmed_vulns=json.dumps(state.get("vulnerability_report", [])[-10:], default=str),
        )

        try:
            from langchain_core.messages import SystemMessage, HumanMessage

            messages = [
                SystemMessage(content=PLANNER_SYSTEM_PROMPT),
                HumanMessage(content=user_prompt),
            ]

            response = await self._llm.ainvoke(messages)
            response_text = response.content if hasattr(response, "content") else str(response)

            task_tree = self._parse_task_tree(response_text)

            seen = set()
            deduped = []
            for task in task_tree:
                key = f"{task.get('target_endpoint')}:{task.get('vuln_type')}"
                if key not in seen:
                    seen.add(key)
                    deduped.append(task)

            logger.info("planner_global_complete", tasks=len(deduped))

            return {
                "task_tree": deduped,
                "untested_surface": remaining_untested,
                "current_phase": "planning_complete",
            }

        except Exception as e:
            logger.error("planner_llm_error", error=str(e))
            return {
                "task_tree": [],
                "untested_surface": remaining_untested,
                "current_phase": "planning_complete",
                "errors": list(state.get("errors", []))
                + [{"phase": "planner", "error": str(e), "time": time.time()}],
            }

    def _build_page_prompt(self, analysis: Any, capture: Any, state: ApexState) -> str:
        """Build the user prompt for page-mode planning."""
        # Attack vectors from analyzer
        vectors = analysis.get("attack_vectors", [])
        vectors_str = (
            json.dumps(vectors, indent=2, default=str)[:5000] if vectors else "None identified"
        )

        # Recommended tasks from analyzer
        rec_tasks = analysis.get("recommended_tasks", [])
        rec_str = json.dumps(rec_tasks, indent=2, default=str)[:3000] if rec_tasks else "None"

        # Attack surfaces from capture
        surfaces = []
        forms = []
        requests_summary = []
        sinks = []
        cookies = []
        tech = {}
        surface_count = 0
        form_count = 0
        request_count = 0
        sink_count = 0
        cookie_count = 0

        if capture:
            surfaces = capture.get("attack_surfaces", [])
            surface_count = len(surfaces)
            forms = capture.get("forms", [])
            form_count = len(forms)

            raw_requests = capture.get("network_requests", [])
            request_count = len(raw_requests)
            for req in raw_requests[:25]:
                requests_summary.append(
                    {
                        "url": req.get("url", ""),
                        "method": req.get("method", ""),
                        "status": req.get("response_status", 0),
                        "type": req.get("resource_type", ""),
                        "has_body": bool(req.get("request_body", "")),
                    }
                )

            sinks = capture.get("dom_sinks", [])
            sink_count = len(sinks)
            cookies = capture.get("cookies_set", [])
            cookie_count = len(cookies)
            tech = capture.get("tech_signals", {})

        surfaces_str = (
            json.dumps(surfaces[:25], indent=2, default=str)[:5000] if surfaces else "None"
        )
        forms_str = json.dumps(forms[:10], indent=2, default=str)[:3000] if forms else "None"
        requests_str = json.dumps(requests_summary, indent=2)[:4000] if requests_summary else "None"
        sinks_str = json.dumps(sinks[:15], indent=2, default=str)[:2000] if sinks else "None"
        cookies_str = json.dumps(cookies[:15], indent=2, default=str)[:1500] if cookies else "None"
        tech_str = json.dumps(tech, indent=2, default=str)[:1500] if tech else "None"

        waf = state.get("waf_profile", {})
        waf_info = f"Detected: {waf.get('detected', False)}, Name: {waf.get('waf_name', 'none')}, Safe Rate: {waf.get('safe_request_rate', 10)}/s"

        auth_matrix = state.get("auth_matrix", [])
        auth_roles = (
            ", ".join(t.get("role", "?") for t in auth_matrix)
            if auth_matrix
            else "unauthenticated only"
        )

        prev_vulns = state.get("vulnerability_report", [])
        prev_str = (
            json.dumps(prev_vulns[-5:], indent=2, default=str)[:2000] if prev_vulns else "None yet"
        )

        return PLANNER_PAGE_TEMPLATE.format(
            page_url=analysis.get("url", ""),
            page_title=capture.get("page_title", "") if capture else "",
            risk_score=analysis.get("risk_score", 0),
            interest_level=analysis.get("interest_level", "unknown"),
            analysis_reasoning=analysis.get("reasoning", ""),
            attack_vectors=vectors_str,
            recommended_tasks=rec_str,
            surface_count=surface_count,
            attack_surfaces=surfaces_str,
            form_count=form_count,
            forms=forms_str,
            request_count=request_count,
            network_requests=requests_str,
            sink_count=sink_count,
            dom_sinks=sinks_str,
            cookie_count=cookie_count,
            cookies=cookies_str,
            tech_signals=tech_str,
            target_url=state.get("target_url", ""),
            waf_info=waf_info,
            auth_roles=auth_roles,
            deep_scan=state.get("deep_scan_active", False),
            prev_vulns=prev_str,
        )

    def _parse_task_tree(self, llm_response: str) -> list[TaskItem]:
        """Parse the LLM's JSON response into TaskItem objects."""
        text = llm_response.strip()
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()

        try:
            raw_tasks = json.loads(text)
        except json.JSONDecodeError:
            import re

            match = re.search(r"\[.*\]", text, re.DOTALL)
            if match:
                try:
                    raw_tasks = json.loads(match.group())
                except json.JSONDecodeError:
                    logger.warning("planner_json_parse_failed")
                    return []
            else:
                return []

        tasks = []
        for raw in raw_tasks:
            task = TaskItem(
                task_id=raw.get("task_id", f"task-{uuid.uuid4().hex[:8]}"),
                target_endpoint=raw.get("target_endpoint", ""),
                target_method=raw.get("target_method", "GET"),
                target_params=raw.get("target_params", []),
                vuln_type=raw.get("vuln_type", "unknown"),
                owasp_category=raw.get("owasp_category", ""),
                recommended_tool=raw.get("recommended_tool", "custom_script"),
                payloads=raw.get("payloads", []),
                priority=raw.get("priority", 3),
                status="pending",
                result=None,
            )
            tasks.append(task)

        return tasks

    def _convert_analyzer_tasks(self, analysis: Any, page_url: str) -> list[TaskItem]:
        """Convert PageAnalysis recommended_tasks to TaskItems as fallback."""
        tasks = []
        for rec in analysis.get("recommended_tasks", []):
            task = TaskItem(
                task_id=f"task-{uuid.uuid4().hex[:8]}",
                target_endpoint=rec.get("target", page_url),
                target_method=rec.get("method", "GET"),
                target_params=rec.get("params", []),
                vuln_type=rec.get("task_type", "unknown"),
                owasp_category="",
                recommended_tool="custom_script",
                payloads=[],
                priority=3,
                status="pending",
                result=None,
            )
            tasks.append(task)

        # Also convert attack vectors to basic tasks
        for vector in analysis.get("attack_vectors", []):
            task = TaskItem(
                task_id=f"task-{uuid.uuid4().hex[:8]}",
                target_endpoint=vector.get("target_element", page_url),
                target_method="GET",
                target_params=[],
                vuln_type=vector.get("type", "unknown"),
                owasp_category="",
                recommended_tool="custom_script",
                payloads=[],
                priority=vector.get("priority", 3),
                status="pending",
                result=None,
            )
            tasks.append(task)

        return tasks
