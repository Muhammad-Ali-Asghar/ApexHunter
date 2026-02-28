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
        vulnerabilities: list[Vulnerability] = list(
            state.get("vulnerability_report", [])
        )
        state_changing: list[ProxyLogEntry] = list(
            state.get("state_changing_requests", [])
        )

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

    async def _route_task(
        self, task: TaskItem, auth_matrix: list, state: ApexState
    ) -> dict:
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
                evidence = f"Endpoint accessible without authentication (status: {unauth['status']})"

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
        concurrent_count = (
            self._config.agent.max_concurrent_requests if self._config else 20
        )

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
            introspection_query = (
                '{"query":"{ __schema { types { name fields { name } } } }"}'
            )
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
                except Exception:
                    pass

        return {"vulnerable": False}

    # ── Path E: Infrastructure ─────────────────────────────
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
        """Direct injection testing without LLM script generation."""
        endpoint = task.get("target_endpoint", "")
        method = task.get("target_method", "GET")
        params = task.get("target_params", [])
        payloads = task.get("payloads", [])

        if not payloads:
            return {"vulnerable": False}

        # Get baseline response
        baseline = await self._http.request(
            method=method, url=endpoint, auth_role="scanner"
        )
        if baseline is None:
            return {"vulnerable": False}

        baseline_text = baseline.text
        baseline_status = baseline.status_code

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

            body = resp.text.lower()

            # Check for SQL error indicators
            sql_errors = [
                "sql syntax",
                "mysql",
                "postgresql",
                "sqlite",
                "ora-",
                "mssql",
                "unclosed quotation",
                "syntax error",
                "unexpected end of sql",
                "warning: mysql",
            ]
            for err in sql_errors:
                if err in body and err not in baseline_text.lower():
                    return {
                        "vulnerable": True,
                        "evidence": f"SQL error triggered by payload: {payload}",
                        "details": {"payload": payload, "error_indicator": err},
                        "status_code": resp.status_code,
                    }

            # Check for XSS reflection
            if payload in resp.text and payload not in baseline_text:
                return {
                    "vulnerable": True,
                    "evidence": f"Payload reflected in response: {payload}",
                    "details": {"payload": payload, "reflected": True},
                    "status_code": resp.status_code,
                }

            # Check for SSTI
            if "49" in resp.text and "{{7*7}}" in payload:
                return {
                    "vulnerable": True,
                    "evidence": "Server-side template injection: {{7*7}} evaluated to 49",
                    "details": {"payload": payload},
                    "status_code": resp.status_code,
                }

            await asyncio.sleep(0.2)

        return {"vulnerable": False}

    def _create_vulnerability(self, task: TaskItem, result: dict) -> Vulnerability:
        """Create a Vulnerability object from task results."""
        vuln_type = task.get("vuln_type", "unknown")

        severity_map = {
            "sqli": ("critical", 9.8),
            "sqli_error": ("critical", 9.8),
            "sqli_blind": ("critical", 9.8),
            "xss_reflected": ("high", 7.5),
            "xss_dom": ("high", 7.5),
            "ssti": ("critical", 9.8),
            "ssrf": ("critical", 9.1),
            "lfi": ("critical", 9.1),
            "idor": ("high", 7.5),
            "bac": ("critical", 9.8),
            "race_condition": ("medium", 5.9),
            "cors_misconfiguration": ("medium", 5.3),
            "missing_security_headers": ("low", 3.5),
            "http_smuggling": ("critical", 9.8),
            "cache_poisoning": ("high", 7.5),
            "graphql_introspection": ("medium", 5.3),
            "open_redirect": ("medium", 4.7),
        }

        severity, cvss = severity_map.get(vuln_type, ("medium", 5.0))

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
            evidence=result.get("evidence", ""),
            request_sent=json.dumps(result.get("details", {}), default=str)[:2000],
            response_received="",
            remediation=self._get_remediation(vuln_type),
            discovered_at=time.time(),
            validated=True,
            is_second_order=False,
            chain_parent=None,
        )

    def _get_remediation(self, vuln_type: str) -> str:
        """Return remediation advice for a vulnerability type."""
        remediations = {
            "sqli": "Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
            "sqli_error": "Use parameterized queries. Disable verbose error messages in production.",
            "xss_reflected": "Encode all user input before rendering. Implement Content-Security-Policy.",
            "xss_dom": "Avoid using innerHTML/eval. Use textContent for DOM manipulation.",
            "ssti": "Use safe template rendering. Never pass user input directly to template engines.",
            "ssrf": "Validate and whitelist allowed URLs. Block internal IP ranges.",
            "lfi": "Validate file paths. Use a whitelist of allowed files. Chroot the application.",
            "idor": "Implement proper authorization checks. Use indirect object references.",
            "bac": "Enforce role-based access control. Verify permissions on every request.",
            "race_condition": "Use database-level locks or atomic operations for state-changing actions.",
            "cors_misconfiguration": "Restrict Access-Control-Allow-Origin. Never use wildcard with credentials.",
            "missing_security_headers": "Add all recommended security headers (CSP, HSTS, X-Frame-Options).",
            "http_smuggling": "Normalize HTTP parsing. Use HTTP/2 end-to-end.",
            "cache_poisoning": "Strip unrecognized headers before caching. Use cache keys properly.",
            "graphql_introspection": "Disable introspection in production. Implement query depth limiting.",
            "open_redirect": "Validate redirect URLs against a whitelist. Never use user-controlled redirect targets.",
        }
        return remediations.get(
            vuln_type, "Review and fix the identified vulnerability."
        )
