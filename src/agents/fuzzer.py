"""
Fuzzer Agent (Node 5 - Exhaustive Deep Fuzzing)

Uses massive wordlists + OSINT historical data to exhaustively
brute-force hidden directories, legacy APIs, and developer parameters.
Configured for exhaustive search — time is not a constraint.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any, Optional
from urllib.parse import urlparse, urljoin

import structlog

from src.state import ApexState, Endpoint
from src.tools.cli_wrappers import run_ffuf

logger = structlog.get_logger("apexhunter.agents.fuzzer")

# ── Built-in directory wordlist (used when SecLists is unavailable) ──
BUILTIN_DIRS = [
    "admin",
    "api",
    "api/v1",
    "api/v2",
    "api/v3",
    "api/internal",
    "backup",
    "backups",
    "bak",
    "bin",
    "cgi-bin",
    "config",
    "console",
    "cp",
    "dashboard",
    "db",
    "debug",
    "dev",
    "docs",
    "download",
    "dump",
    "env",
    "error",
    "export",
    "files",
    "graphql",
    "health",
    "healthcheck",
    "help",
    "hidden",
    "import",
    "include",
    "info",
    "init",
    "install",
    "internal",
    "json",
    "legacy",
    "log",
    "login",
    "logout",
    "manage",
    "management",
    "metrics",
    "monitor",
    "old",
    "panel",
    "phpinfo.php",
    "ping",
    "private",
    "profile",
    "public",
    "readme",
    "register",
    "reset",
    "rest",
    "rpc",
    "secret",
    "server-info",
    "server-status",
    "settings",
    "setup",
    "shell",
    "sitemap.xml",
    "staging",
    "static",
    "status",
    "swagger",
    "sys",
    "system",
    "temp",
    "test",
    "testing",
    "tmp",
    "token",
    "tools",
    "trace",
    "upload",
    "uploads",
    "user",
    "users",
    "v1",
    "v2",
    "v3",
    "version",
    "web",
    "webhook",
    "webhooks",
    "wp-admin",
    "wp-content",
    "wp-includes",
    "wp-login.php",
    "xml",
    "xmlrpc.php",
    ".git",
    ".git/HEAD",
    ".git/config",
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".htaccess",
    ".htpasswd",
    ".svn",
    ".svn/entries",
    "robots.txt",
    "sitemap.xml",
    "crossdomain.xml",
    "clientaccesspolicy.xml",
    "security.txt",
    ".well-known/security.txt",
    "favicon.ico",
    "wp-config.php.bak",
    "config.php.bak",
    "web.config",
    "package.json",
    "composer.json",
    "Gemfile",
    "requirements.txt",
]

# ── Built-in parameter wordlist ──
BUILTIN_PARAMS = [
    "id",
    "user_id",
    "userId",
    "uid",
    "username",
    "email",
    "password",
    "token",
    "key",
    "api_key",
    "apiKey",
    "secret",
    "debug",
    "test",
    "admin",
    "role",
    "type",
    "action",
    "cmd",
    "command",
    "exec",
    "query",
    "search",
    "q",
    "page",
    "limit",
    "offset",
    "sort",
    "order",
    "filter",
    "callback",
    "redirect",
    "redirect_url",
    "redirectUrl",
    "return",
    "return_url",
    "returnUrl",
    "next",
    "url",
    "file",
    "filename",
    "path",
    "dir",
    "folder",
    "include",
    "template",
    "view",
    "format",
    "output",
    "download",
    "upload",
    "lang",
    "language",
    "locale",
    "ref",
    "source",
    "from",
    "to",
    "start",
    "end",
    "date",
    "time",
    "name",
    "title",
    "description",
    "content",
    "body",
    "message",
    "comment",
    "text",
    "data",
    "json",
    "xml",
    "category",
    "tag",
    "status",
    "state",
    "mode",
    "level",
    "config",
    "setting",
    "option",
    "value",
    "param",
    "access_token",
    "refresh_token",
    "session",
    "sid",
    "csrf",
    "csrf_token",
    "_token",
    "nonce",
    "proxy",
    "host",
    "port",
    "server",
    "domain",
    "width",
    "height",
    "size",
    "color",
    "theme",
    "v",
    "version",
    "ver",
    "rev",
    "build",
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "test_user_id",
    "admin_override",
    "bypass",
    "internal",
    "_debug",
    "_test",
    "_admin",
    "_internal",
    "_dev",
]


class FuzzerAgent:
    """
    Exhaustive Deep Fuzzer.

    Brute-forces hidden directories and parameters using:
    1. Built-in wordlists
    2. SecLists (if available in /app/data/seclists)
    3. Historical OSINT data from Node 2
    4. ffuf CLI tool (if installed)
    """

    def __init__(self, http_client: Any, config: Any):
        self._http = http_client
        self._config = config

    async def run(self, state: ApexState) -> dict:
        """Execute the exhaustive fuzzing phase."""
        target_url = state.get("target_url", "")
        existing_endpoints = list(state.get("discovered_endpoints", []))
        osint_endpoints = list(state.get("hidden_surface_map", []))

        logger.info("fuzzer_start", target=target_url)

        new_endpoints: list[Endpoint] = []

        # Phase 1: Directory brute-forcing
        dir_results = await self._fuzz_directories(target_url)
        new_endpoints.extend(dir_results)

        # Phase 2: Parameter discovery on known endpoints
        param_results = await self._fuzz_parameters(target_url, existing_endpoints)
        new_endpoints.extend(param_results)

        # Phase 3: Fuzz OSINT-discovered historical endpoints
        osint_results = await self._fuzz_osint_endpoints(osint_endpoints)
        new_endpoints.extend(osint_results)

        # Phase 4: Sensitive file discovery
        sensitive_results = await self._fuzz_sensitive_files(target_url)
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

    async def _fuzz_directories(self, target_url: str) -> list[Endpoint]:
        """Brute-force directories using ffuf or fallback HTTP."""
        results: list[Endpoint] = []

        # Try ffuf first
        import shutil

        if shutil.which("ffuf"):
            # Check for SecLists wordlist
            wordlist = (
                "/app/data/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
            )
            if not os.path.exists(wordlist):
                wordlist = "/app/data/seclists/Discovery/Web-Content/common.txt"
            if not os.path.exists(wordlist):
                # Create temp wordlist from built-in
                wordlist = "/tmp/apex_dirs.txt"
                with open(wordlist, "w") as f:
                    f.write("\n".join(BUILTIN_DIRS))

            fuzz_url = f"{target_url.rstrip('/')}/FUZZ"
            try:
                ffuf_results = await run_ffuf(
                    target_url=fuzz_url,
                    wordlist=wordlist,
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

        # Fallback: HTTP-based directory fuzzing
        logger.info("fuzzer_http_fallback", reason="ffuf not available")
        tasks = []
        for directory in BUILTIN_DIRS:
            url = f"{target_url.rstrip('/')}/{directory}"
            tasks.append(self._check_url_exists(url, "fuzz_dir"))

        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in batch_results:
            if isinstance(result, dict) and "url" in result:
                results.append(result)  # type: ignore[arg-type]

        return results

    async def _fuzz_parameters(
        self, target_url: str, endpoints: list[Endpoint]
    ) -> list[Endpoint]:
        """Discover hidden parameters on known endpoints."""
        results: list[Endpoint] = []

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
            for param in BUILTIN_PARAMS:
                test_url = f"{ep_url}?{param}=test"
                tasks.append(self._check_param_response(ep_url, param))

            batch = await asyncio.gather(*tasks, return_exceptions=True)
            for result in batch:
                if isinstance(result, dict) and result.get("found"):
                    results.append(
                        Endpoint(
                            url=ep_url,
                            method="GET",
                            params=[
                                {"name": result["param"], "type": "query", "value": ""}
                            ],
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

    async def _fuzz_osint_endpoints(
        self, osint_endpoints: list[Endpoint]
    ) -> list[Endpoint]:
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
                if isinstance(result, dict) and "url" in result:
                    results.append(result)  # type: ignore[arg-type]

        logger.info(
            "fuzzer_osint_verified", alive=len(results), total=len(osint_endpoints)
        )
        return results

    async def _fuzz_sensitive_files(self, target_url: str) -> list[Endpoint]:
        """Check for exposed sensitive files and directories."""
        results: list[Endpoint] = []
        sensitive_paths = [
            ".git/HEAD",
            ".git/config",
            ".env",
            ".env.local",
            ".env.production",
            "config.php.bak",
            "web.config",
            ".htaccess",
            ".htpasswd",
            "backup.sql",
            "dump.sql",
            "phpinfo.php",
            "server-status",
            "server-info",
            ".DS_Store",
            "wp-config.php.bak",
            "elmah.axd",
            "trace.axd",
            "__debug__",
            "_debug_toolbar/",
            "actuator",
            "actuator/env",
            "actuator/health",
            "actuator/configprops",
            "actuator/beans",
            "jolokia",
            "jolokia/list",
        ]

        tasks = []
        for path in sensitive_paths:
            url = f"{target_url.rstrip('/')}/{path}"
            tasks.append(self._check_sensitive_file(url))

        batch = await asyncio.gather(*tasks, return_exceptions=True)
        for result in batch:
            if isinstance(result, dict) and "url" in result:
                results.append(result)  # type: ignore[arg-type]

        return results

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
