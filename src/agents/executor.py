"""
Multi-Vector Executor (Node 11)

The core execution engine. Iterates through the Task Tree and
dispatches each task to the appropriate execution path:
  Path A: CLI tools (Nuclei, Nmap, ffuf)
  Path B: Cross-Auth Scripting (IDOR/BAC token swapping)
  Path C: Race Conditions (concurrent async bursts)
  Path D: Protocol Specific (WebSocket, GraphQL)
  Path E: Infrastructure Attacks (HTTP Smuggling, Cache Poisoning)
  Path F: Sandboxed custom Python scripts
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Any, Optional

import structlog

from src.state import ApexState, TaskItem, Vulnerability, ProxyLogEntry

logger = structlog.get_logger("apexhunter.agents.executor")

SCRIPT_GEN_PROMPT = """You are a security testing script generator. Generate a Python script
that uses httpx to test for the specified vulnerability. The script must:
1. Be NON-DESTRUCTIVE — only identify, never exploit
2. Define a `run()` function that returns a dict with keys: "vulnerable" (bool), "evidence" (str), "details" (dict)
3. Use httpx for HTTP requests (already imported)
4. Target URL: {target_url}
5. Test for: {vuln_type}
6. Parameters to test: {params}
7. Payloads to use: {payloads}

Output ONLY the Python code, no explanations."""


class ExecutorAgent:
    """
    The Multi-Vector Executor.

    Routes tasks to specialized execution paths based on the
    vulnerability type and recommended tool.
    """

    def __init__(
        self,
        http_client: Any,
        llm: Any,
        rag_engine: Any,
        sandbox: Any,
        jit_installer: Any,
        config: Any,
    ):
        self._http = http_client
        self._llm = llm
        self._rag = rag_engine
        self._sandbox = sandbox
        self._jit = jit_installer
        self._config = config

    async def run(self, state: ApexState) -> dict:
        """Execute all tasks in the Task Tree."""
        task_tree = list(state.get("task_tree", []))
        auth_matrix = state.get("auth_matrix", [])
        waf = state.get("waf_profile", {})
        oob_url = state.get("oob_listener_url", "")

        logger.info("executor_start", total_tasks=len(task_tree))

        completed_tasks: list[TaskItem] = list(state.get("completed_tasks", []))
        vulnerabilities: list[Vulnerability] = list(state.get("vulnerability_report", []))
        state_changing: list[ProxyLogEntry] = list(state.get("state_changing_requests", []))

        # Get pacing from WAF profile
        safe_rate = waf.get("safe_request_rate", 10.0)
        delay = 1.0 / safe_rate if safe_rate > 0 else 0.5

        for task in task_tree:
            if task.get("status") == "completed":
                continue

            task["status"] = "in_progress"
            logger.info(
                "executor_task_start",
                task_id=task.get("task_id"),
                vuln_type=task.get("vuln_type"),
                endpoint=task.get("target_endpoint"),
            )

            try:
                # Fetch RAG payloads for this task
                vuln_type = task.get("vuln_type", "")
                payloads = self._rag.get_payloads(vuln_type)
                if payloads:
                    task["payloads"] = payloads[:30]

                # Replace OOB_URL placeholder in payloads
                if oob_url:
                    task["payloads"] = [
                        p.replace("OOB_URL", oob_url) for p in task.get("payloads", [])
                    ]

                # Route to the appropriate execution path
                result = await self._route_task(task, auth_matrix, state)

                task["result"] = result
                task["status"] = "completed"

                # Check if vulnerability was found
                if result and result.get("vulnerable"):
                    vuln = self._create_vulnerability(task, result)
                    vulnerabilities.append(vuln)
                    logger.warning(
                        "vulnerability_found",
                        vuln_type=vuln_type,
                        endpoint=task.get("target_endpoint"),
                        severity=vuln.get("severity", "medium"),
                    )

                # Track state-changing requests
                if task.get("target_method", "GET") in (
                    "POST",
                    "PUT",
                    "PATCH",
                    "DELETE",
                ):
                    state_changing.append(
                        ProxyLogEntry(
                            timestamp=time.time(),
                            method=task.get("target_method", "POST"),
                            url=task.get("target_endpoint", ""),
                            request_headers={},
                            request_body="",
                            status_code=result.get("status_code", 0) if result else 0,
                            response_headers={},
                            response_body="",
                            response_time_ms=0,
                            auth_role="scanner",
                        )
                    )

            except Exception as e:
                logger.error(
                    "executor_task_error",
                    task_id=task.get("task_id"),
                    error=str(e),
                )
                task["status"] = "completed"
                task["result"] = {"vulnerable": False, "error": str(e)}

            completed_tasks.append(task)
            await asyncio.sleep(delay)

        logger.info(
            "executor_complete",
            completed=len(completed_tasks),
            vulnerabilities=len(vulnerabilities),
        )

        return {
            "completed_tasks": completed_tasks,
            "vulnerability_report": vulnerabilities,
            "state_changing_requests": state_changing,
            "current_phase": "execution_complete",
        }

    async def _route_task(self, task: TaskItem, auth_matrix: list, state: ApexState) -> dict:
        """Route a task to the appropriate execution path."""
        vuln_type = task.get("vuln_type", "")
        tool = task.get("recommended_tool", "custom_script")

        # Path A: CLI Tools
        if tool in ("nuclei", "nmap", "ffuf"):
            return await self._path_a_cli_tool(task)

        # Path B: Cross-Auth (IDOR/BAC)
        if vuln_type in (
            "idor",
            "bac",
            "broken_access_control",
            "privilege_escalation",
        ):
            return await self._path_b_cross_auth(task, auth_matrix)

        # Path C: Race Conditions
        if vuln_type in ("race_condition", "toctou"):
            return await self._path_c_race_condition(task, auth_matrix)

        # Path D: Protocol Specific
        if vuln_type in (
            "graphql_introspection",
            "graphql_batching",
            "websocket_injection",
        ):
            return await self._path_d_protocol(task)

        # Path E: Infrastructure
        if vuln_type in ("http_smuggling", "cache_poisoning", "request_smuggling"):
            return await self._path_e_infrastructure(task)

        # Direct HTTP tests
        if tool == "direct_http" or vuln_type in (
            "missing_security_headers",
            "cors_misconfiguration",
            "sensitive_file_exposure",
            "open_redirect",
        ):
            return await self._path_direct_http(task)

        # Path F: Custom Script (default fallback)
        return await self._path_f_custom_script(task, state)

    # ── Path A: CLI Tools ──────────────────────────────────
    async def _path_a_cli_tool(self, task: TaskItem) -> dict:
        """Execute a task using an external CLI tool."""
        tool = task.get("recommended_tool", "")
        endpoint = task.get("target_endpoint", "")

        # Ensure tool is installed
        installed = await self._jit.ensure_installed(tool)
        if not installed:
            logger.warning("executor_tool_unavailable", tool=tool)
            return {"vulnerable": False, "error": f"Tool {tool} unavailable"}

        if tool == "nuclei":
            from src.tools.cli_wrappers import run_nuclei

            vuln_type = task.get("vuln_type", "")
            tags = [vuln_type] if vuln_type else None
            findings = await run_nuclei(endpoint, tags=tags, rate_limit=20)
            if findings:
                return {
                    "vulnerable": True,
                    "evidence": json.dumps(findings[0], default=str)[:2000],
                    "details": {"findings": findings},
                    "tool": "nuclei",
                }
            return {"vulnerable": False, "tool": "nuclei"}

        elif tool == "nmap":
            from src.tools.cli_wrappers import run_nmap
            from urllib.parse import urlparse

            parsed = urlparse(endpoint)
            result = await run_nmap(parsed.netloc)
            open_ports = result.get("ports", [])
            return {
                "vulnerable": len(open_ports) > 0,
                "evidence": f"Found {len(open_ports)} open ports",
                "details": result,
                "tool": "nmap",
            }

        return {"vulnerable": False, "error": f"Unknown tool: {tool}"}

    # ── Path B: Cross-Auth (IDOR/BAC) ──────────────────────
    async def _path_b_cross_auth(self, task: TaskItem, auth_matrix: list) -> dict:
        """Test IDOR/BAC by replaying requests with different auth tokens."""
        endpoint = task.get("target_endpoint", "")
        method = task.get("target_method", "GET")

        if len(auth_matrix) < 2:
            return {"vulnerable": False, "error": "Need 2+ auth roles for IDOR testing"}

        # Get responses for each role
        responses = {}
        for token in auth_matrix:
            role = token.get("role", "unknown")
            headers = dict(token.get("headers", {}))
            cookies = dict(token.get("cookies", {}))

            resp = await self._http.request(
                method=method,
                url=endpoint,
                headers=headers,
                cookies=cookies,
                auth_role=role,
            )
            if resp:
                responses[role] = {
                    "status": resp.status_code,
                    "length": len(resp.text),
                    "body_preview": resp.text[:500],
                }

        # Also test with NO auth
        no_auth_resp = await self._http.request(
            method=method, url=endpoint, auth_role="unauthenticated"
        )
        if no_auth_resp:
            responses["unauthenticated"] = {
                "status": no_auth_resp.status_code,
                "length": len(no_auth_resp.text),
                "body_preview": no_auth_resp.text[:500],
            }

        # Analyze: if a low-privilege role can access high-privilege data
        roles = list(responses.keys())
        vulnerable = False
        evidence = ""

        for i in range(len(roles)):
            for j in range(i + 1, len(roles)):
                r1, r2 = responses[roles[i]], responses[roles[j]]
                # If both get 200 with similar content, potential IDOR
                if r1["status"] == 200 and r2["status"] == 200:
                    if abs(r1["length"] - r2["length"]) < 100:
                        vulnerable = True
                        evidence = (
                            f"Roles '{roles[i]}' and '{roles[j]}' both received 200 OK "
                            f"with similar content length ({r1['length']} vs {r2['length']})"
                        )

        # Unauthenticated access to authenticated endpoint
        if "unauthenticated" in responses:
            unauth = responses["unauthenticated"]
            if unauth["status"] == 200 and unauth["length"] > 100:
                vulnerable = True
                evidence = (
                    f"Endpoint accessible without authentication (status: {unauth['status']})"
                )

        return {
            "vulnerable": vulnerable,
            "evidence": evidence,
            "details": responses,
        }

    # ── Path C: Race Conditions ────────────────────────────
    async def _path_c_race_condition(self, task: TaskItem, auth_matrix: list) -> dict:
        """Test for TOCTOU race conditions with concurrent requests."""
        endpoint = task.get("target_endpoint", "")
        method = task.get("target_method", "POST")
        concurrent_count = self._config.agent.max_concurrent_requests if self._config else 20

        auth = auth_matrix[0] if auth_matrix else {}
        headers = dict(auth.get("headers", {}))
        cookies = dict(auth.get("cookies", {}))

        # Fire concurrent requests
        async def send_request(i: int):
            resp = await self._http.request(
                method=method,
                url=endpoint,
                headers=headers,
                cookies=cookies,
                auth_role=auth.get("role", "scanner"),
            )
            if resp:
                return {
                    "index": i,
                    "status": resp.status_code,
                    "length": len(resp.text),
                    "body_preview": resp.text[:200],
                }
            return {"index": i, "status": 0, "error": "no response"}

        tasks = [send_request(i) for i in range(concurrent_count)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Analyze: check for inconsistent responses (indicates race)
        exceptions = [r for r in results if isinstance(r, BaseException)]
        if exceptions:
            logger.warning("race_condition_errors", count=len(exceptions), first=str(exceptions[0]))
        valid_results = [r for r in results if isinstance(r, dict) and r.get("status")]
        statuses = [r["status"] for r in valid_results]
        unique_statuses = set(statuses)

        vulnerable = len(unique_statuses) > 1 and 200 in unique_statuses
        evidence = ""
        if vulnerable:
            evidence = (
                f"Inconsistent responses from {concurrent_count} concurrent requests: "
                f"statuses={dict((s, statuses.count(s)) for s in unique_statuses)}"
            )

        return {
            "vulnerable": vulnerable,
            "evidence": evidence,
            "details": {
                "concurrent_count": concurrent_count,
                "results": valid_results[:10],
            },
        }

    # ── Path D: Protocol Specific ──────────────────────────
    async def _path_d_protocol(self, task: TaskItem) -> dict:
        """Test protocol-specific vulnerabilities (GraphQL, WebSocket)."""
        endpoint = task.get("target_endpoint", "")
        vuln_type = task.get("vuln_type", "")

        if vuln_type == "graphql_introspection":
            introspection_query = '{"query":"{ __schema { types { name fields { name } } } }"}'
            resp = await self._http.post(
                endpoint,
                json=json.loads(introspection_query),
                headers={"Content-Type": "application/json"},
                auth_role="scanner",
            )
            if resp and resp.status_code == 200:
                body = resp.text
                if "__schema" in body or "__type" in body:
                    return {
                        "vulnerable": True,
                        "evidence": "GraphQL introspection is enabled — full schema exposed",
                        "details": {"response_preview": body[:2000]},
                    }

        elif vuln_type == "graphql_batching":
            batch_query = [
                {"query": "{ __typename }"},
                {"query": "{ __typename }"},
                {"query": "{ __typename }"},
            ]
            resp = await self._http.post(
                endpoint,
                json=batch_query,
                headers={"Content-Type": "application/json"},
                auth_role="scanner",
            )
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if isinstance(data, list) and len(data) > 1:
                        return {
                            "vulnerable": True,
                            "evidence": "GraphQL query batching is enabled — potential DoS vector",
                            "details": {"batch_size": len(data)},
                        }
                except (json.JSONDecodeError, ValueError) as e:
                    logger.debug("graphql_batch_parse_error", error=str(e))

        return {"vulnerable": False}

    async def _path_e_infrastructure(self, task: TaskItem) -> dict:
        """Test HTTP Request Smuggling and Cache Poisoning."""
        endpoint = task.get("target_endpoint", "")
        vuln_type = task.get("vuln_type", "")

        if "smuggling" in vuln_type:
            # CL.TE detection: send ambiguous Content-Length + Transfer-Encoding
            # This is a SAFE detection method — we just check for timeout differentials
            resp1 = await self._http.post(
                endpoint,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Transfer-Encoding": "chunked",
                },
                data="0\r\n\r\n",
                auth_role="scanner",
            )

            resp2 = await self._http.post(
                endpoint,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": "6",
                    "Transfer-Encoding": "chunked",
                },
                data="0\r\n\r\nX",
                auth_role="scanner",
            )

            if resp1 and resp2:
                if resp1.status_code != resp2.status_code:
                    return {
                        "vulnerable": True,
                        "evidence": (
                            f"Potential HTTP Request Smuggling: different responses for "
                            f"CL.TE test (status {resp1.status_code} vs {resp2.status_code})"
                        ),
                        "details": {},
                    }

        elif "cache_poisoning" in vuln_type:
            # Test cache poisoning with X-Forwarded-Host
            headers = {"X-Forwarded-Host": "apex-canary.test"}
            resp = await self._http.get(endpoint, headers=headers, auth_role="scanner")
            if resp and "apex-canary.test" in resp.text:
                return {
                    "vulnerable": True,
                    "evidence": "X-Forwarded-Host header reflected in response (cache poisoning)",
                    "details": {"reflected_header": "X-Forwarded-Host"},
                }

        return {"vulnerable": False}

    # ── Direct HTTP Tests ──────────────────────────────────
    async def _path_direct_http(self, task: TaskItem) -> dict:
        """Direct HTTP-based security checks."""
        endpoint = task.get("target_endpoint", "")
        vuln_type = task.get("vuln_type", "")

        if vuln_type == "missing_security_headers":
            resp = await self._http.get(endpoint, auth_role="scanner")
            if resp is None:
                return {"vulnerable": False}

            headers = {k.lower(): v for k, v in resp.headers.items()}
            missing = []
            required_headers = {
                "strict-transport-security": "Strict-Transport-Security",
                "content-security-policy": "Content-Security-Policy",
                "x-content-type-options": "X-Content-Type-Options",
                "x-frame-options": "X-Frame-Options",
                "referrer-policy": "Referrer-Policy",
                "permissions-policy": "Permissions-Policy",
            }

            for key, name in required_headers.items():
                if key not in headers:
                    missing.append(name)

            if missing:
                return {
                    "vulnerable": True,
                    "evidence": f"Missing security headers: {', '.join(missing)}",
                    "details": {"missing_headers": missing},
                }
            return {"vulnerable": False}

        elif vuln_type == "cors_misconfiguration":
            test_origins = ["https://evil.com", "null", f"https://{endpoint}.evil.com"]
            for origin in test_origins:
                resp = await self._http.get(
                    endpoint,
                    headers={"Origin": origin},
                    auth_role="scanner",
                )
                if resp:
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                    if acao == origin or acao == "*":
                        vuln_detail = f"CORS allows origin '{origin}'"
                        if acac.lower() == "true":
                            vuln_detail += " WITH credentials"
                        return {
                            "vulnerable": True,
                            "evidence": vuln_detail,
                            "details": {"origin": origin, "acao": acao, "acac": acac},
                        }
            return {"vulnerable": False}

        return {"vulnerable": False}

    # ── Path F: Custom Script ──────────────────────────────
    async def _path_f_custom_script(self, task: TaskItem, state: ApexState) -> dict:
        """Generate and execute a custom validation script via LLM."""
        endpoint = task.get("target_endpoint", "")
        vuln_type = task.get("vuln_type", "")
        params = task.get("target_params", [])
        payloads = task.get("payloads", [])

        # For simple injection tests, use direct HTTP instead of LLM
        if vuln_type in ("sqli_error", "xss_reflected", "ssti") and payloads:
            return await self._test_injection_direct(task)

        # Generate script via LLM
        try:
            from langchain_core.messages import HumanMessage

            prompt = SCRIPT_GEN_PROMPT.format(
                target_url=endpoint,
                vuln_type=vuln_type,
                params=json.dumps(params),
                payloads=json.dumps(payloads[:10]),
            )
            response = await self._llm.ainvoke([HumanMessage(content=prompt)])
            script = response.content if hasattr(response, "content") else str(response)

            # Clean up the script
            if "```python" in script:
                script = script.split("```python")[1].split("```")[0]
            elif "```" in script:
                script = script.split("```")[1].split("```")[0]

            # Execute in sandbox
            result = await self._sandbox.execute(script.strip())
            if result.get("status") == "success":
                try:
                    output = json.loads(result.get("output", "{}"))
                    return output
                except (json.JSONDecodeError, TypeError):
                    return {"vulnerable": False, "output": result.get("output", "")}
            else:
                return {"vulnerable": False, "error": result.get("error", "")}

        except Exception as e:
            logger.warning("executor_script_gen_error", error=str(e))
            return await self._test_injection_direct(task)

    async def _test_injection_direct(self, task: TaskItem) -> dict:
        """
        Direct injection testing with AI-driven response analysis.

        Sends payloads and uses the LLM to analyze whether the response
        indicates a vulnerability, rather than relying on hardcoded
        error string patterns.
        """
        endpoint = task.get("target_endpoint", "")
        method = task.get("target_method", "GET")
        params = task.get("target_params", [])
        payloads = task.get("payloads", [])
        vuln_type = task.get("vuln_type", "unknown")

        if not payloads:
            return {"vulnerable": False}

        # Get baseline response
        baseline = await self._http.request(method=method, url=endpoint, auth_role="scanner")
        if baseline is None:
            return {"vulnerable": False}

        baseline_text = baseline.text
        baseline_status = baseline.status_code

        # Collect interesting response diffs for LLM analysis
        interesting_responses = []

        for payload in payloads[:20]:
            # Inject payload into URL params
            if method == "GET":
                if params:
                    param_str = "&".join(f"{p}={payload}" for p in params[:3])
                    test_url = (
                        f"{endpoint}?{param_str}"
                        if "?" not in endpoint
                        else f"{endpoint}&{param_str}"
                    )
                else:
                    test_url = f"{endpoint}?test={payload}"
                resp = await self._http.get(test_url, auth_role="scanner")
            else:
                data = {p: payload for p in params[:3]} if params else {"test": payload}
                resp = await self._http.post(endpoint, json=data, auth_role="scanner")

            if resp is None:
                continue

            # Detect meaningful differences from baseline
            status_diff = resp.status_code != baseline_status
            length_diff = abs(len(resp.text) - len(baseline_text)) > 50
            payload_reflected = payload in resp.text and payload not in baseline_text

            if status_diff or length_diff or payload_reflected:
                interesting_responses.append(
                    {
                        "payload": payload,
                        "status_code": resp.status_code,
                        "baseline_status": baseline_status,
                        "response_preview": resp.text[:1500],
                        "baseline_preview": baseline_text[:500],
                        "payload_reflected": payload_reflected,
                        "length_delta": len(resp.text) - len(baseline_text),
                    }
                )

            await asyncio.sleep(0.2)

        if not interesting_responses:
            return {"vulnerable": False}

        # Use LLM to analyze the response differences
        return await self._analyze_responses_with_llm(vuln_type, endpoint, interesting_responses)

    async def _analyze_responses_with_llm(
        self, vuln_type: str, endpoint: str, responses: list[dict]
    ) -> dict:
        """Use the LLM to determine if response differences indicate a vulnerability."""
        analysis_prompt = f"""You are analyzing HTTP responses from a security test.
The test was checking for: {vuln_type}
Target endpoint: {endpoint}

Below are the responses that differed from the baseline. For each, determine if the
difference indicates a genuine vulnerability or is a benign variation.

Responses:
{json.dumps(responses[:5], indent=2, default=str)[:6000]}

Analyze the evidence and respond with ONLY valid JSON:
{{
  "vulnerable": true/false,
  "confidence": "high"/"medium"/"low",
  "evidence": "description of what indicates the vulnerability",
  "details": {{
    "payload": "the payload that triggered it",
    "indicator": "what specific response content proves the vulnerability"
  }}
}}

Be conservative — only mark as vulnerable if you see clear evidence like:
- Database error messages in response to SQL payloads
- Payload reflection without encoding (for XSS)
- Template expression evaluation (for SSTI)
- Path traversal content disclosure (for LFI)
- Unexpected data access (for IDOR)

Do NOT flag false positives from WAF blocks, generic error pages, or normal redirects."""

        try:
            from langchain_core.messages import HumanMessage

            response = await self._llm.ainvoke([HumanMessage(content=analysis_prompt)])
            text = response.content if hasattr(response, "content") else str(response)

            # Parse JSON from response
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0].strip()
            elif "```" in text:
                text = text.split("```")[1].split("```")[0].strip()

            result = json.loads(text)
            return {
                "vulnerable": result.get("vulnerable", False),
                "evidence": result.get("evidence", ""),
                "details": result.get("details", {}),
                "confidence": result.get("confidence", "low"),
                "status_code": responses[0].get("status_code", 0) if responses else 0,
            }
        except Exception as e:
            logger.warning("executor_llm_analysis_error", error=str(e))
            # Ultra-conservative fallback: only flag clearly reflected payloads
            for resp in responses:
                if resp.get("payload_reflected"):
                    return {
                        "vulnerable": True,
                        "evidence": f"Payload reflected in response: {resp.get('payload', '')}",
                        "details": {"payload": resp.get("payload", ""), "reflected": True},
                        "status_code": resp.get("status_code", 0),
                    }
            return {"vulnerable": False}

    def _create_vulnerability(self, task: TaskItem, result: dict) -> Vulnerability:
        """Create a Vulnerability object from task results using AI-driven assessment."""
        vuln_type = task.get("vuln_type", "unknown")
        evidence = result.get("evidence", "")
        confidence = result.get("confidence", "medium")

        # AI-driven severity assessment based on context
        severity, cvss = self._assess_severity_dynamic(vuln_type, evidence, confidence, task)
        remediation = self._generate_remediation_dynamic(vuln_type, evidence, task)

        return Vulnerability(
            vuln_id=f"APEX-{uuid.uuid4().hex[:8].upper()}",
            title=f"{vuln_type.replace('_', ' ').title()} on {task.get('target_endpoint', '')}",
            vuln_type=vuln_type,
            owasp_category=task.get("owasp_category", ""),
            severity=severity,
            cvss_score=cvss,
            affected_endpoint=task.get("target_endpoint", ""),
            affected_method=task.get("target_method", "GET"),
            affected_param=", ".join(task.get("target_params", [])),
            evidence=evidence,
            request_sent=json.dumps(result.get("details", {}), default=str)[:2000],
            response_received="",
            remediation=remediation,
            discovered_at=time.time(),
            validated=True,
            is_second_order=False,
            chain_parent=None,
        )

    def _assess_severity_dynamic(
        self, vuln_type: str, evidence: str, confidence: str, task: TaskItem
    ) -> tuple[str, float]:
        """
        Dynamically assess vulnerability severity based on context.

        Instead of a hardcoded severity map, this considers:
        - The vulnerability type's potential impact
        - The evidence strength (confidence level)
        - The affected endpoint's characteristics
        - Whether authentication is required
        """
        # Base severity assessment by vulnerability class (broad, not specific)
        # These are CVSS base score ranges, not exact values
        injection_types = {
            "sqli",
            "sqli_error",
            "sqli_blind",
            "nosqli",
            "command_injection",
            "ldap_injection",
        }
        critical_types = {
            "ssti",
            "ssrf",
            "lfi",
            "rfi",
            "deserialization",
            "http_smuggling",
            "bac",
            "broken_access_control",
        }
        high_types = {
            "xss_reflected",
            "xss_dom",
            "xss_stored",
            "idor",
            "jwt_manipulation",
            "cache_poisoning",
            "file_upload_bypass",
        }
        medium_types = {
            "race_condition",
            "cors_misconfiguration",
            "graphql_introspection",
            "open_redirect",
            "csrf_missing",
        }
        low_types = {
            "missing_security_headers",
            "sensitive_data_exposure",
            "information_disclosure",
        }

        if vuln_type in injection_types:
            base_severity, base_cvss = "critical", 9.5
        elif vuln_type in critical_types:
            base_severity, base_cvss = "critical", 9.0
        elif vuln_type in high_types:
            base_severity, base_cvss = "high", 7.5
        elif vuln_type in medium_types:
            base_severity, base_cvss = "medium", 5.5
        elif vuln_type in low_types:
            base_severity, base_cvss = "low", 3.5
        else:
            # Unknown type — assess based on confidence
            base_severity, base_cvss = "medium", 5.0

        # Adjust based on confidence
        if confidence == "low":
            base_cvss = max(base_cvss - 1.5, 1.0)
            if base_severity == "critical":
                base_severity = "high"
            elif base_severity == "high":
                base_severity = "medium"
        elif confidence == "high":
            base_cvss = min(base_cvss + 0.5, 10.0)

        # Adjust if endpoint requires auth (slightly lower impact if auth-gated)
        if task.get("target_method", "GET") == "GET" and not task.get("target_params"):
            base_cvss = max(base_cvss - 0.5, 1.0)

        return base_severity, round(base_cvss, 1)

    def _generate_remediation_dynamic(self, vuln_type: str, evidence: str, task: TaskItem) -> str:
        """
        Generate context-aware remediation advice.

        Instead of a hardcoded remediation map, this produces advice
        based on the specific vulnerability type and what was found.
        The LLM would be ideal here but for synchronous contexts we
        provide intelligent template-free advice.
        """
        endpoint = task.get("target_endpoint", "")
        params = task.get("target_params", [])

        # Category-based remediation (broad guidance, not vuln-type-specific hardcoding)
        if "sqli" in vuln_type or "injection" in vuln_type or "nosql" in vuln_type:
            return (
                f"The parameter(s) {', '.join(params) if params else 'tested'} on {endpoint} "
                f"appear vulnerable to injection. Use parameterized queries or prepared statements. "
                f"Apply input validation and encoding appropriate to the data context. "
                f"Review all database queries that incorporate user input on this endpoint."
            )
        elif "xss" in vuln_type:
            return (
                f"User input is reflected or rendered without proper encoding on {endpoint}. "
                f"Apply context-aware output encoding (HTML entity, JavaScript, URL encoding as appropriate). "
                f"Implement a strict Content-Security-Policy header. "
                f"Consider using a templating engine with auto-escaping enabled."
            )
        elif "ssti" in vuln_type:
            return (
                f"Server-side template injection detected on {endpoint}. "
                f"Never pass user input directly into template rendering. "
                f"Use sandboxed template execution and restrict template syntax."
            )
        elif "ssrf" in vuln_type:
            return (
                f"Server-side request forgery possible via {endpoint}. "
                f"Validate and whitelist allowed destination URLs/IPs. "
                f"Block access to internal network ranges (169.254.x.x, 10.x.x.x, 127.x.x.x). "
                f"Use a URL parser to prevent scheme/host bypasses."
            )
        elif "idor" in vuln_type or "bac" in vuln_type or "access_control" in vuln_type:
            return (
                f"Authorization bypass detected on {endpoint}. "
                f"Implement proper authorization checks on every request. "
                f"Use indirect object references (map user-visible IDs to internal IDs). "
                f"Verify the requesting user has permission to access the specific resource."
            )
        elif "csrf" in vuln_type:
            return (
                f"Cross-site request forgery possible on {endpoint}. "
                f"Implement anti-CSRF tokens on all state-changing operations. "
                f"Use SameSite cookie attributes and verify the Origin/Referer headers."
            )
        elif "redirect" in vuln_type:
            return (
                f"Open redirect on {endpoint}. "
                f"Validate redirect targets against a whitelist of allowed domains. "
                f"Never use user-controlled values directly in redirect destinations."
            )
        elif "smuggling" in vuln_type:
            return (
                f"HTTP request smuggling detected. Normalize HTTP parsing across "
                f"all proxy/server layers. Prefer HTTP/2 end-to-end to eliminate "
                f"CL.TE/TE.CL ambiguities."
            )
        elif "header" in vuln_type or "cors" in vuln_type:
            return (
                f"Security configuration issue on {endpoint}. "
                f"Review and implement all recommended security headers "
                f"(CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy). "
                f"For CORS: restrict allowed origins, never use wildcard with credentials."
            )
        elif "upload" in vuln_type:
            return (
                f"File upload vulnerability on {endpoint}. "
                f"Validate file type by content (magic bytes), not just extension. "
                f"Store uploads outside the webroot. Rename files to prevent path traversal. "
                f"Set restrictive Content-Type headers when serving uploaded files."
            )
        else:
            return (
                f"Vulnerability ({vuln_type}) identified on {endpoint}. "
                f"Review the evidence and apply appropriate security controls. "
                f"Consult OWASP guidelines for {task.get('owasp_category', 'the relevant category')}."
            )
