"""
Threat & Logic Planner (Node 8 - Cloud LLM)

Analyzes the reduced attack surface, proxy logs, and DOM sinks.
Uses a powerful Cloud LLM to draft a comprehensive Task Tree
covering OWASP Top 10, Business Logic flaws, and Race Conditions.
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
You are analyzing a web application's attack surface to create a comprehensive,
non-destructive vulnerability testing plan.

Your task is to generate a prioritized list of security tests (Task Tree) based on
the reconnaissance data provided. Each task must be:
1. NON-DESTRUCTIVE — identification only, no exploitation
2. Targeted at a specific endpoint and parameter
3. Mapped to an OWASP Top 10 category
4. Assigned a priority (1=critical, 5=low)

OWASP Top 10 (2021) categories to consider:
- A01: Broken Access Control (IDOR, privilege escalation, forced browsing)
- A02: Cryptographic Failures (weak TLS, exposed secrets)
- A03: Injection (SQLi, NoSQLi, XSS, SSTI, Command Injection, LDAP)
- A04: Insecure Design (business logic flaws, negative quantities, race conditions)
- A05: Security Misconfiguration (default creds, exposed debug, missing headers)
- A06: Vulnerable Components (outdated libraries with known CVEs)
- A07: Auth Failures (weak passwords, session fixation, JWT flaws)
- A08: Software/Data Integrity (deserialization, CI/CD issues)
- A09: Logging/Monitoring Failures (insufficient logging)
- A10: SSRF (Server-Side Request Forgery)

Also consider:
- HTTP Request Smuggling (CL.TE, TE.CL)
- Web Cache Poisoning
- CORS Misconfiguration
- Open Redirects
- DOM-based XSS (from sink data)
- Race Conditions (TOCTOU on state-changing endpoints)
- Business Logic flaws (negative values, bypassing workflows)

For each test, specify:
- task_id: unique identifier
- target_endpoint: the URL template to test
- target_method: HTTP method
- target_params: list of parameter names to inject into
- vuln_type: specific vulnerability type (e.g., "sqli_error", "idor", "xss_reflected")
- owasp_category: OWASP category code (e.g., "A03")
- recommended_tool: one of "nuclei", "custom_script", "ffuf", "nmap", "direct_http"
- priority: 1-5

Output ONLY valid JSON array of task objects. No explanation text."""

PLANNER_USER_TEMPLATE = """## Target Information
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

Generate a comprehensive Task Tree for non-destructive vulnerability testing. If there are Confirmed Vulnerabilities, generate tasks to deeply explore them (Impact Proofing). If the Attack Surface is empty and no vulnerabilities need pivoting, return an empty JSON array []."""


class PlannerAgent:
    """
    The Strategic Planner — uses a Cloud LLM to generate
    a comprehensive, prioritized Task Tree.
    """

    def __init__(self, llm: Any):
        self._llm = llm

    async def run(self, state: ApexState) -> dict:
        """Execute the planning phase."""
        target_url = state.get("target_url", "")
        if not target_url:
            logger.error("planner_no_target_url")
            return {"task_tree": [], "current_phase": "planning_skipped"}

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

        logger.info("planner_start", batch_size=len(batch), remaining=len(remaining_untested))

        # Format the data for the LLM
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

        user_prompt = PLANNER_USER_TEMPLATE.format(
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

        # Call the LLM
        try:
            from langchain_core.messages import SystemMessage, HumanMessage

            messages = [
                SystemMessage(content=PLANNER_SYSTEM_PROMPT),
                HumanMessage(content=user_prompt),
            ]

            response = await self._llm.ainvoke(messages)
            response_text = response.content if hasattr(response, "content") else str(response)

            # Parse the Task Tree from the LLM response
            task_tree = self._parse_task_tree(response_text)

            # Add standard tests that should always be run
            task_tree.extend(self._generate_standard_tasks(state, batch))

            # Deduplicate by (endpoint, vuln_type)
            seen = set()
            deduped = []
            for task in task_tree:
                key = f"{task.get('target_endpoint')}:{task.get('vuln_type')}"
                if key not in seen:
                    seen.add(key)
                    deduped.append(task)

            logger.info("planner_complete", tasks=len(deduped))

            return {
                "task_tree": deduped,
                "untested_surface": remaining_untested,
                "current_phase": "planning_complete",
            }

        except Exception as e:
            logger.error("planner_llm_error", error=str(e))
            # Fallback: generate a basic task tree without LLM
            fallback_tasks = self._generate_standard_tasks(state, batch)
            return {
                "task_tree": fallback_tasks,
                "untested_surface": remaining_untested,
                "current_phase": "planning_complete",
                "errors": list(state.get("errors", []))
                + [{"phase": "planner", "error": str(e), "time": time.time()}],
            }

    def _parse_task_tree(self, llm_response: str) -> list[TaskItem]:
        """Parse the LLM's JSON response into TaskItem objects."""
        # Extract JSON from the response (handle markdown code blocks)
        text = llm_response.strip()
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()

        try:
            raw_tasks = json.loads(text)
        except json.JSONDecodeError:
            # Try to find JSON array in the text
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
                payloads=[],
                priority=raw.get("priority", 3),
                status="pending",
                result=None,
            )
            tasks.append(task)

        return tasks

    def _generate_standard_tasks(
        self, state: ApexState, batch: list[dict[str, Any]]
    ) -> list[TaskItem]:
        """Generate standard tasks that should always be tested for the current batch."""
        target_url = state.get("target_url", "")
        auth_matrix = state.get("auth_matrix", [])
        tasks: list[TaskItem] = []

        # Only run these global checks on the very first iteration
        if state.get("iteration_count", 0) == 0 and batch:
            # Security Headers Check
            tasks.append(
                TaskItem(
                    task_id=f"std-headers-{uuid.uuid4().hex[:6]}",
                    target_endpoint=target_url,
                    target_method="GET",
                    target_params=[],
                    vuln_type="missing_security_headers",
                    owasp_category="A05",
                    recommended_tool="direct_http",
                    payloads=[],
                    priority=3,
                    status="pending",
                    result=None,
                )
            )

            # CORS Misconfiguration
            tasks.append(
                TaskItem(
                    task_id=f"std-cors-{uuid.uuid4().hex[:6]}",
                    target_endpoint=target_url,
                    target_method="GET",
                    target_params=[],
                    vuln_type="cors_misconfiguration",
                    owasp_category="A05",
                    recommended_tool="direct_http",
                    payloads=[],
                    priority=2,
                    status="pending",
                    result=None,
                )
            )

        # IDOR tests for endpoints with ID parameters
        if len(auth_matrix) >= 2:
            for ep in batch[:20]:
                template = ep.get("template", "")
                if "{id}" in template or "{uuid}" in template:
                    tasks.append(
                        TaskItem(
                            task_id=f"std-idor-{uuid.uuid4().hex[:6]}",
                            target_endpoint=ep.get("example_url", template),
                            target_method=ep.get("method", "GET"),
                            target_params=["id"],
                            vuln_type="idor",
                            owasp_category="A01",
                            recommended_tool="custom_script",
                            payloads=[],
                            priority=1,
                            status="pending",
                            result=None,
                        )
                    )

        # Race condition tests for POST endpoints
        for ep in batch[:15]:
            if ep.get("method", "GET") in ("POST", "PUT", "PATCH"):
                tasks.append(
                    TaskItem(
                        task_id=f"std-race-{uuid.uuid4().hex[:6]}",
                        target_endpoint=ep.get("example_url", ep.get("template", "")),
                        target_method=ep.get("method", "POST"),
                        target_params=ep.get("params", []),
                        vuln_type="race_condition",
                        owasp_category="A04",
                        recommended_tool="custom_script",
                        payloads=[],
                        priority=2,
                        status="pending",
                        result=None,
                    )
                )

        return tasks
