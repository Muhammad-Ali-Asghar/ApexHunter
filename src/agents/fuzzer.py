"""
Fuzzer Agent (Node 5 - Exhaustive Deep Fuzzing)

Uses LLM-generated contextual wordlists + OSINT historical data to
exhaustively discover hidden directories, legacy APIs, and developer
parameters. All wordlists are generated dynamically by the AI based on
the target's technology stack — nothing is hardcoded.
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Optional
from urllib.parse import urlparse, urljoin

import structlog

from src.state import ApexState, Endpoint
from src.tools.cli_wrappers import run_ffuf

logger = structlog.get_logger("apexhunter.agents.fuzzer")


class FuzzerAgent:
    """
    Exhaustive Deep Fuzzer (AI-Driven).

    Brute-forces hidden directories and parameters using:
    1. LLM-generated contextual wordlists (based on target tech stack)
    2. SecLists (if available in /app/data/seclists)
    3. Historical OSINT data from Node 2
    4. ffuf CLI tool (if installed)

    No hardcoded wordlists — the AI generates them based on what it
    knows about the target.
    """

    def __init__(self, http_client: Any, config: Any, llm: Any = None):
        self._http = http_client
        self._config = config
        self._llm = llm
        self._dir_cache: list[str] | None = None
        self._param_cache: list[str] | None = None
        self._sensitive_cache: list[str] | None = None

    # ── LLM-Driven Wordlist Generation ──────────────────────

    def _build_tech_context(self, state: ApexState) -> str:
        """Build a tech-context string from everything we know about the target."""
        parts = []
        target_url = state.get("target_url", "")
        if target_url:
            parts.append(f"Target URL: {target_url}")

        tech_fp = state.get("technology_fingerprint", {})
        if tech_fp:
            parts.append(f"Technology fingerprint: {json.dumps(tech_fp)}")

        # Summarize known endpoints (sample)
        endpoints = state.get("discovered_endpoints", [])
        if endpoints:
            sample = [ep.get("url", "") for ep in endpoints[:20]]
            parts.append(f"Known endpoints (sample of {len(endpoints)}): {sample}")

        osint = state.get("historical_osint_data", [])
        if osint:
            parts.append(f"OSINT data points: {len(osint)}")

        return "\n".join(parts) if parts else "No tech context available."

    async def _generate_directory_wordlist(self, state: ApexState) -> list[str]:
        """Ask the LLM to generate a contextual directory wordlist."""
        if self._dir_cache is not None:
            return self._dir_cache

        if not self._llm:
            logger.warning("fuzzer_no_llm_for_dirs", msg="No LLM — cannot generate wordlist")
            return []

        tech_context = self._build_tech_context(state)

        prompt = f"""You are a web application security expert generating a directory/path wordlist
for brute-force discovery. Based on the target's technology stack, generate
paths that are most likely to exist and reveal hidden functionality.

{tech_context}

Generate a JSON array of 100-200 directory/file paths to check. Include:
- Admin panels, dashboards, management interfaces
- API versioned endpoints (v1, v2, internal)
- Configuration/debug/status endpoints
- Backup files, source code leaks, VCS artifacts (.git, .svn)
- Framework-specific paths (based on detected technology)
- Common sensitive files (.env, config backups, SQL dumps)
- CI/CD artifacts, deployment scripts
- Health/metrics/monitoring endpoints

Return ONLY a JSON array of strings, no explanation. Example:
["admin", "api/v1", ".git/HEAD", ".env"]"""

        try:
            from langchain_core.messages import HumanMessage

            response = await self._llm.ainvoke([HumanMessage(content=prompt)])
            text = response.content.strip()

            # Extract JSON array from response
            if "```" in text:
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            text = text.strip()

            dirs = json.loads(text)
            if isinstance(dirs, list):
                self._dir_cache = [str(d).strip().strip("/") for d in dirs if d]
                logger.info("fuzzer_llm_dirs_generated", count=len(self._dir_cache))
                return self._dir_cache
        except Exception as e:
            logger.warning("fuzzer_llm_dir_generation_failed", error=str(e))

        return []

    async def _generate_parameter_wordlist(self, state: ApexState) -> list[str]:
        """Ask the LLM to generate a contextual parameter wordlist."""
        if self._param_cache is not None:
            return self._param_cache

        if not self._llm:
            logger.warning("fuzzer_no_llm_for_params", msg="No LLM — cannot generate wordlist")
            return []

        tech_context = self._build_tech_context(state)

        prompt = f"""You are a web application security expert generating a parameter wordlist
for hidden parameter discovery. Based on the target's technology stack,
generate parameter names that are most likely to reveal hidden functionality
or be vulnerable to injection.

{tech_context}

Generate a JSON array of 80-150 parameter names to test. Include:
- Authentication params (token, api_key, session, etc.)
- Debug/admin params (debug, test, admin, internal, bypass)
- Injection-prone params (query, search, cmd, exec, file, path, url, redirect)
- IDOR params (id, user_id, uid, account_id)
- Framework-specific params (based on detected technology)
- Hidden/internal params (_debug, _test, _admin, _internal)
- CSRF/nonce params
- Pagination/filter params

Return ONLY a JSON array of strings, no explanation."""

        try:
            from langchain_core.messages import HumanMessage

            response = await self._llm.ainvoke([HumanMessage(content=prompt)])
            text = response.content.strip()

            if "```" in text:
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            text = text.strip()

            params = json.loads(text)
            if isinstance(params, list):
                self._param_cache = [str(p).strip() for p in params if p]
                logger.info("fuzzer_llm_params_generated", count=len(self._param_cache))
                return self._param_cache
        except Exception as e:
            logger.warning("fuzzer_llm_param_generation_failed", error=str(e))

        return []

    async def _generate_sensitive_paths(self, state: ApexState) -> list[str]:
        """Ask the LLM to generate sensitive file paths based on target context."""
        if self._sensitive_cache is not None:
            return self._sensitive_cache

        if not self._llm:
            logger.warning("fuzzer_no_llm_for_sensitive", msg="No LLM — cannot generate paths")
            return []

        tech_context = self._build_tech_context(state)

        prompt = f"""You are a web application security expert. Based on the target's technology
stack, generate a list of sensitive file/directory paths that could expose
confidential data, credentials, or internal configuration if publicly accessible.

{tech_context}

Generate a JSON array of 30-60 sensitive paths. Include:
- Version control artifacts (.git/HEAD, .svn/entries)
- Environment files (.env, .env.production)
- Configuration backups (config.php.bak, web.config, wp-config.php.bak)
- Database dumps (backup.sql, dump.sql)
- Debug endpoints (phpinfo.php, server-status, __debug__)
- Framework-specific debug/admin (actuator/*, elmah.axd, trace.axd)
- Package manifests (package.json, composer.json, Gemfile)
- CI/CD files (.github/workflows, Jenkinsfile, .gitlab-ci.yml)
- Anything else specific to the detected technologies

Return ONLY a JSON array of strings, no explanation."""

        try:
            from langchain_core.messages import HumanMessage

            response = await self._llm.ainvoke([HumanMessage(content=prompt)])
            text = response.content.strip()

            if "```" in text:
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            text = text.strip()

            paths = json.loads(text)
            if isinstance(paths, list):
                self._sensitive_cache = [str(p).strip().lstrip("/") for p in paths if p]
                logger.info("fuzzer_llm_sensitive_generated", count=len(self._sensitive_cache))
                return self._sensitive_cache
        except Exception as e:
            logger.warning("fuzzer_llm_sensitive_generation_failed", error=str(e))

        return []

    # ── Main Run ──────────────────────────────────────────

    async def run(self, state: ApexState) -> dict:
        """Execute the exhaustive fuzzing phase."""
        target_url = state.get("target_url", "")
        if not target_url:
            logger.warning("fuzzer_no_target_url")
            return {"current_phase": "fuzzing_skipped"}
        existing_endpoints = list(state.get("discovered_endpoints", []))
        osint_endpoints = list(state.get("hidden_surface_map", []))

        logger.info("fuzzer_start", target=target_url)

        # Generate all wordlists in parallel from the LLM
        dir_words, param_words, sensitive_words = await asyncio.gather(
            self._generate_directory_wordlist(state),
            self._generate_parameter_wordlist(state),
            self._generate_sensitive_paths(state),
        )

        logger.info(
            "fuzzer_wordlists_ready",
            dirs=len(dir_words),
            params=len(param_words),
            sensitive=len(sensitive_words),
        )

        new_endpoints: list[Endpoint] = []

        # Phase 1: Directory brute-forcing
        dir_results = await self._fuzz_directories(target_url, dir_words)
        new_endpoints.extend(dir_results)

        # Phase 2: Parameter discovery on known endpoints
        param_results = await self._fuzz_parameters(target_url, existing_endpoints, param_words)
        new_endpoints.extend(param_results)

        # Phase 3: Fuzz OSINT-discovered historical endpoints
        osint_results = await self._fuzz_osint_endpoints(osint_endpoints)
        new_endpoints.extend(osint_results)

        # Phase 4: Sensitive file discovery
        sensitive_results = await self._fuzz_sensitive_files(target_url, sensitive_words)
        new_endpoints.extend(sensitive_results)

        # Deduplicate
        seen_urls = set()
        deduped: list[Endpoint] = []
        for ep in new_endpoints:
            key = f"{ep.get('method', 'GET')}:{ep.get('url', '')}"
            if key not in seen_urls:
                seen_urls.add(key)
                deduped.append(ep)

        # Merge with existing
        all_endpoints = existing_endpoints + deduped

        logger.info(
            "fuzzer_complete",
            new_endpoints=len(deduped),
            total_endpoints=len(all_endpoints),
        )

        return {
            "discovered_endpoints": all_endpoints,
            "hidden_surface_map": osint_endpoints + deduped,
            "current_phase": "fuzzing_complete",
        }

    # ── Fuzzing Phases ────────────────────────────────────

    async def _fuzz_directories(self, target_url: str, dir_wordlist: list[str]) -> list[Endpoint]:
        """Brute-force directories using ffuf or fallback HTTP."""
        results: list[Endpoint] = []

        if not dir_wordlist:
            logger.warning("fuzzer_no_dir_wordlist", msg="LLM did not generate any dirs")
            return results

        # Try ffuf first
        import shutil

        if shutil.which("ffuf"):
            # Check for SecLists wordlist first (larger coverage)
            seclists = "/app/data/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
            if not os.path.exists(seclists):
                seclists = "/app/data/seclists/Discovery/Web-Content/common.txt"

            if os.path.exists(seclists):
                wordlist_path = seclists
            else:
                # Write LLM-generated wordlist to temp file for ffuf
                wordlist_path = "/tmp/apex_dirs.txt"
                with open(wordlist_path, "w") as f:
                    f.write("\n".join(dir_wordlist))

            fuzz_url = f"{target_url.rstrip('/')}/FUZZ"
            try:
                ffuf_results = await run_ffuf(
                    target_url=fuzz_url,
                    wordlist=wordlist_path,
                    rate_limit=100,
                    timeout=600,
                )
                for entry in ffuf_results:
                    results.append(
                        Endpoint(
                            url=entry.get("url", ""),
                            method="GET",
                            params=[],
                            headers={},
                            content_type="",
                            requires_auth=False,
                            source="fuzz_dir",
                        )
                    )
                return results
            except Exception as e:
                logger.warning("ffuf_failed", error=str(e))

        # Fallback: HTTP-based directory fuzzing with LLM-generated wordlist
        logger.info("fuzzer_http_fallback", reason="ffuf not available")
        tasks = []
        for directory in dir_wordlist:
            url = f"{target_url.rstrip('/')}/{directory}"
            tasks.append(self._check_url_exists(url, "fuzz_dir"))

        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in batch_results:
            if isinstance(result, BaseException):
                logger.debug("fuzz_dir_error", error=str(result))
                continue
            if isinstance(result, dict) and "url" in result:
                results.append(result)  # type: ignore[arg-type]

        return results

    async def _fuzz_parameters(
        self,
        target_url: str,
        endpoints: list[Endpoint],
        param_wordlist: list[str],
    ) -> list[Endpoint]:
        """Discover hidden parameters on known endpoints."""
        results: list[Endpoint] = []

        if not param_wordlist:
            logger.warning("fuzzer_no_param_wordlist", msg="LLM did not generate any params")
            return results

        # Select a subset of endpoints to fuzz for parameters
        endpoints_to_fuzz = []
        for ep in endpoints[:50]:  # Limit to first 50 to avoid explosion
            url = ep.get("url", "")
            if url and "?" not in url:
                endpoints_to_fuzz.append(url)

        if not endpoints_to_fuzz:
            endpoints_to_fuzz = [target_url]

        for ep_url in endpoints_to_fuzz[:20]:
            tasks = []
            for param in param_wordlist:
                tasks.append(self._check_param_response(ep_url, param))

            batch = await asyncio.gather(*tasks, return_exceptions=True)
            for result in batch:
                if isinstance(result, BaseException):
                    logger.debug("fuzz_param_error", error=str(result))
                    continue
                if isinstance(result, dict) and result.get("found"):
                    results.append(
                        Endpoint(
                            url=ep_url,
                            method="GET",
                            params=[{"name": result["param"], "type": "query", "value": ""}],
                            headers={},
                            content_type="",
                            requires_auth=False,
                            source="fuzz_param",
                        )
                    )

        return results

    async def _check_param_response(self, url: str, param: str) -> dict:
        """Check if a parameter causes a different response."""
        # Get baseline response
        baseline = await self._http.get(url, auth_role="scanner")
        if baseline is None:
            return {"found": False, "param": param}

        # Test with parameter
        test_url = f"{url}?{param}=1"
        test_resp = await self._http.get(test_url, auth_role="scanner")
        if test_resp is None:
            return {"found": False, "param": param}

        # Compare responses — if significantly different, parameter is accepted
        baseline_len = len(baseline.text)
        test_len = len(test_resp.text)

        if test_resp.status_code != baseline.status_code:
            return {"found": True, "param": param}

        if abs(baseline_len - test_len) > 50:
            return {"found": True, "param": param}

        return {"found": False, "param": param}

    async def _fuzz_osint_endpoints(self, osint_endpoints: list[Endpoint]) -> list[Endpoint]:
        """Verify that OSINT-discovered historical endpoints are still alive."""
        results: list[Endpoint] = []
        tasks = []

        for ep in osint_endpoints[:200]:
            url = ep.get("url", "")
            if url:
                tasks.append(self._check_url_exists(url, "fuzz_osint"))

        if tasks:
            batch = await asyncio.gather(*tasks, return_exceptions=True)
            for result in batch:
                if isinstance(result, BaseException):
                    logger.debug("fuzz_osint_error", error=str(result))
                    continue
                if isinstance(result, dict) and "url" in result:
                    results.append(result)  # type: ignore[arg-type]

        logger.info("fuzzer_osint_verified", alive=len(results), total=len(osint_endpoints))
        return results

    async def _fuzz_sensitive_files(
        self, target_url: str, sensitive_paths: list[str]
    ) -> list[Endpoint]:
        """Check for exposed sensitive files and directories (LLM-generated paths)."""
        results: list[Endpoint] = []

        if not sensitive_paths:
            logger.warning("fuzzer_no_sensitive_paths", msg="LLM did not generate any paths")
            return results

        tasks = []
        for path in sensitive_paths:
            url = f"{target_url.rstrip('/')}/{path}"
            tasks.append(self._check_sensitive_file(url))

        batch = await asyncio.gather(*tasks, return_exceptions=True)
        for result in batch:
            if isinstance(result, BaseException):
                logger.debug("fuzz_sensitive_error", error=str(result))
                continue
            if isinstance(result, dict) and "url" in result:
                results.append(result)  # type: ignore[arg-type]

        return results

    # ── HTTP Check Helpers ────────────────────────────────

    async def _check_url_exists(self, url: str, source: str) -> Optional[Endpoint]:
        """Check if a URL returns a valid response."""
        response = await self._http.get(url, auth_role="scanner")
        if response and response.status_code < 404:
            return Endpoint(
                url=url,
                method="GET",
                params=[],
                headers=dict(response.headers),
                content_type=response.headers.get("content-type", ""),
                requires_auth=False,
                source=source,
            )
        return None

    async def _check_sensitive_file(self, url: str) -> Optional[Endpoint]:
        """Check for a sensitive file and flag it."""
        response = await self._http.get(url, auth_role="scanner")
        if response and response.status_code == 200:
            # Verify it's not a custom 404 page
            body = response.text.lower()
            if "not found" not in body and "404" not in body and len(body) > 10:
                logger.warning("sensitive_file_found", url=url)
                return Endpoint(
                    url=url,
                    method="GET",
                    params=[],
                    headers=dict(response.headers),
                    content_type=response.headers.get("content-type", ""),
                    requires_auth=False,
                    source="fuzz_sensitive",
                )
        return None
