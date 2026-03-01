"""
Recon Agent (Node 4 - The Spider)

DOM-aware reconnaissance using Playwright. Crawls the target application,
maps all endpoints, extracts forms and parameters, hunts for API schemas,
and injects DOM tainting hooks to monitor client-side sinks.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Any, Optional
from urllib.parse import urlparse, urljoin, parse_qs

import structlog

from src.state import ApexState, Endpoint

logger = structlog.get_logger("apexhunter.agents.recon")

# JavaScript hook injected into every page to monitor dangerous sinks
DOM_TAINT_HOOK = """
(function() {
    window.__apex_dom_sinks = [];

    // Monitor innerHTML assignments
    const origInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    Object.defineProperty(Element.prototype, 'innerHTML', {
        set: function(value) {
            if (value && typeof value === 'string' && value.length > 0) {
                window.__apex_dom_sinks.push({
                    type: 'innerHTML',
                    element: this.tagName,
                    value: value.substring(0, 500),
                    timestamp: Date.now()
                });
            }
            return origInnerHTML.set.call(this, value);
        },
        get: function() { return origInnerHTML.get.call(this); }
    });

    // Monitor eval
    const origEval = window.eval;
    window.eval = function(code) {
        window.__apex_dom_sinks.push({
            type: 'eval',
            value: String(code).substring(0, 500),
            timestamp: Date.now()
        });
        return origEval.call(this, code);
    };

    // Monitor document.write
    const origWrite = document.write;
    document.write = function(content) {
        window.__apex_dom_sinks.push({
            type: 'document.write',
            value: String(content).substring(0, 500),
            timestamp: Date.now()
        });
        return origWrite.call(this, content);
    };

    // Monitor setTimeout/setInterval with string args
    const origSetTimeout = window.setTimeout;
    window.setTimeout = function(fn, delay) {
        if (typeof fn === 'string') {
            window.__apex_dom_sinks.push({
                type: 'setTimeout_string',
                value: fn.substring(0, 500),
                timestamp: Date.now()
            });
        }
        return origSetTimeout.apply(this, arguments);
    };

    // Monitor postMessage
    window.addEventListener('message', function(e) {
        window.__apex_dom_sinks.push({
            type: 'postMessage',
            origin: e.origin,
            value: JSON.stringify(e.data).substring(0, 500),
            timestamp: Date.now()
        });
    });
})();
"""


class ReconAgent:
    """
    The Spider — DOM-aware reconnaissance engine.

    1. Hunts for API schemas (swagger.json, openapi.yaml, GraphQL)
    2. Crawls the visual application via Playwright
    3. Injects DOM tainting hooks to detect client-side sinks
    4. Captures all network requests through the proxy
    """

    def __init__(self, http_client: Any, config: Any):
        self._http = http_client
        self._config = config
        self._visited_urls: set[str] = set()
        self._discovered_endpoints: list[Endpoint] = []
        self._api_schemas: list[dict] = []
        self._dom_sinks: list[dict] = []
        self._tech_fingerprint: dict[str, Any] = {}
        self._network_requests: list[dict] = []

    async def run(self, state: ApexState) -> dict:
        """Execute the reconnaissance phase."""
        target_url = state.get("target_url", "")
        auth_matrix = state.get("auth_matrix", [])
        max_depth = self._config.target.max_depth if self._config else 10

        if not target_url:
            logger.error("recon_no_target_url")
            return {"current_phase": "recon_skipped"}

        logger.info("recon_start", target=target_url, max_depth=max_depth)

        # Phase 1: Hunt for API schemas
        await self._hunt_api_schemas(target_url)

        # Phase 2: Crawl the application with Playwright
        primary_auth = auth_matrix[0] if auth_matrix else None
        await self._crawl_with_playwright(target_url, primary_auth, max_depth)

        # Phase 2.5: Deep map with Katana
        await self._crawl_with_katana(target_url, primary_auth, max_depth)

        # Phase 3: Fingerprint technologies from captured data
        self._fingerprint_technologies()

        # Merge with existing OSINT endpoints
        existing = list(state.get("hidden_surface_map", []))
        all_endpoints = existing + self._discovered_endpoints

        logger.info(
            "recon_complete",
            endpoints=len(self._discovered_endpoints),
            api_schemas=len(self._api_schemas),
            dom_sinks=len(self._dom_sinks),
            tech_stack=list(self._tech_fingerprint.keys()),
        )

        return {
            "discovered_endpoints": all_endpoints,
            "openapi_schemas": self._api_schemas,
            "dom_sink_logs": self._dom_sinks,
            "technology_fingerprint": self._tech_fingerprint,
            "current_phase": "recon_complete",
        }

    async def _hunt_api_schemas(self, target_url: str) -> None:
        """Actively search for API documentation endpoints."""
        schema_paths = [
            "/swagger.json",
            "/swagger/v1/swagger.json",
            "/api-docs",
            "/api-docs.json",
            "/openapi.json",
            "/openapi.yaml",
            "/openapi/v1.json",
            "/v1/api-docs",
            "/v2/api-docs",
            "/v3/api-docs",
            "/docs",
            "/redoc",
            "/_api/docs",
            "/graphql",
            "/graphiql",
            "/__graphql",
            "/altair",
            "/playground",
            "/swagger-ui.html",
            "/swagger-ui/",
            "/.well-known/openapi.json",
        ]

        tasks = []
        for path in schema_paths:
            url = urljoin(target_url, path)
            tasks.append(self._check_schema_endpoint(url))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, BaseException):
                logger.debug("schema_check_error", error=str(result))
                continue
            if isinstance(result, dict) and result.get("found"):
                self._api_schemas.append(result)
                # Parse OpenAPI/Swagger to extract endpoints
                if result.get("schema"):
                    self._parse_openapi_schema(result["schema"], target_url)

    async def _check_schema_endpoint(self, url: str) -> dict:
        """Check if a URL returns an API schema."""
        response = await self._http.get(url, auth_role="scanner")
        if response is None:
            return {"found": False, "url": url}

        if response.status_code == 200:
            content_type = response.headers.get("content-type", "")
            body = response.text

            # Check for JSON API schema
            if "json" in content_type or body.strip().startswith("{"):
                try:
                    schema = json.loads(body)
                    if any(k in schema for k in ["swagger", "openapi", "paths", "info"]):
                        logger.info("api_schema_found", url=url)
                        return {
                            "found": True,
                            "url": url,
                            "schema": schema,
                            "type": "openapi",
                        }
                except json.JSONDecodeError:
                    pass

            # Check for GraphQL introspection
            if "graphql" in url.lower() or "graphiql" in url.lower():
                logger.info("graphql_endpoint_found", url=url)
                return {"found": True, "url": url, "schema": None, "type": "graphql"}

        return {"found": False, "url": url}

    def _parse_openapi_schema(self, schema: dict, base_url: str) -> None:
        """Parse an OpenAPI/Swagger schema into Endpoint objects."""
        paths = schema.get("paths", {})

        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() not in (
                    "get",
                    "post",
                    "put",
                    "delete",
                    "patch",
                    "options",
                ):
                    continue

                url = urljoin(base_url, path)
                params = []

                # Extract parameters
                for param in details.get("parameters", []):
                    params.append(
                        {
                            "name": param.get("name", ""),
                            "type": param.get("in", "query"),
                            "required": param.get("required", False),
                            "schema": param.get("schema", {}),
                        }
                    )

                # Extract request body parameters
                request_body = details.get("requestBody", {})
                if request_body:
                    content = request_body.get("content", {})
                    for ct, schema_def in content.items():
                        props = schema_def.get("schema", {}).get("properties", {})
                        for prop_name, prop_schema in props.items():
                            params.append(
                                {
                                    "name": prop_name,
                                    "type": "body",
                                    "required": prop_name
                                    in schema_def.get("schema", {}).get("required", []),
                                    "schema": prop_schema,
                                }
                            )

                endpoint = Endpoint(
                    url=url,
                    method=method.upper(),
                    params=params,
                    headers={},
                    content_type=details.get("consumes", ["application/json"])[0]
                    if details.get("consumes")
                    else "application/json",
                    requires_auth=bool(details.get("security")),
                    source="openapi",
                )
                self._discovered_endpoints.append(endpoint)

    async def _crawl_with_playwright(
        self, target_url: str, auth: Optional[Any], max_depth: int
    ) -> None:
        """Crawl the target using Playwright with DOM tainting."""
        try:
            from playwright.async_api import async_playwright

            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    ignore_https_errors=True,
                    viewport={"width": 1280, "height": 720},
                )

                # Set auth cookies if available
                if auth and auth.get("cookies"):
                    parsed = urlparse(target_url)
                    cookie_list = []
                    for name, value in auth["cookies"].items():
                        cookie_list.append(
                            {
                                "name": name,
                                "value": value,
                                "domain": parsed.netloc,
                                "path": "/",
                            }
                        )
                    await context.add_cookies(cookie_list)

                page = await context.new_page()

                # Intercept network requests
                async def on_request(request):
                    self._network_requests.append(
                        {
                            "url": request.url,
                            "method": request.method,
                            "headers": dict(request.headers),
                            "post_data": request.post_data,
                            "resource_type": request.resource_type,
                        }
                    )

                page.on("request", on_request)

                # Inject DOM taint hook before navigation
                await page.add_init_script(DOM_TAINT_HOOK)

                # Start crawling
                urls_to_visit = [(target_url, 0)]

                while urls_to_visit and len(self._visited_urls) < 500:
                    url, depth = urls_to_visit.pop(0)

                    if depth > max_depth:
                        continue
                    if url in self._visited_urls:
                        continue

                    # Normalize URL
                    parsed = urlparse(url)
                    target_parsed = urlparse(target_url)

                    # Looser hostname matching (allow ports to differ, or allow subdomains)
                    if parsed.hostname and target_parsed.hostname:
                        if not parsed.hostname.endswith(target_parsed.hostname):
                            continue

                    self._visited_urls.add(url)

                    try:
                        response = await page.goto(url, wait_until="networkidle", timeout=15000)
                        if not response:
                            continue

                        # Record endpoint
                        endpoint = Endpoint(
                            url=url,
                            method="GET",
                            params=[],
                            headers=dict(response.headers) if response.headers else {},
                            content_type=response.headers.get("content-type", "")
                            if response.headers
                            else "",
                            requires_auth=False,
                            source="crawl",
                        )

                        # Extract query params
                        if parsed.query:
                            params_list = endpoint.get("params", [])
                            for key, values in parse_qs(parsed.query).items():
                                params_list.append(
                                    {
                                        "name": key,
                                        "value": values[0] if values else "",
                                        "type": "query",
                                    }
                                )
                            endpoint["params"] = params_list

                        self._discovered_endpoints.append(endpoint)

                        # Extract links from the page
                        links = await page.evaluate("""() => {
                            const links = [];
                            document.querySelectorAll('a[href]').forEach(a => {
                                links.push(a.href);
                            });
                            document.querySelectorAll('form').forEach(form => {
                                links.push(JSON.stringify({
                                    action: form.action,
                                    method: form.method,
                                    inputs: Array.from(form.querySelectorAll('input,select,textarea')).map(i => ({
                                        name: i.name,
                                        type: i.type,
                                        id: i.id
                                    }))
                                }));
                            });
                            return links;
                        }""")

                        for link in links:
                            if isinstance(link, str):
                                if link.startswith("{"):
                                    # Form data
                                    try:
                                        form_data = json.loads(link)
                                        form_endpoint = Endpoint(
                                            url=form_data.get("action", url),
                                            method=form_data.get("method", "POST").upper(),
                                            params=[
                                                {
                                                    "name": inp["name"],
                                                    "type": "body",
                                                    "input_type": inp.get("type", ""),
                                                }
                                                for inp in form_data.get("inputs", [])
                                                if inp.get("name")
                                            ],
                                            headers={},
                                            content_type="application/x-www-form-urlencoded",
                                            requires_auth=False,
                                            source="crawl_form",
                                        )
                                        self._discovered_endpoints.append(form_endpoint)
                                    except json.JSONDecodeError:
                                        pass
                                else:
                                    absolute_url = urljoin(url, link)
                                    urls_to_visit.append((absolute_url, depth + 1))

                        # Collect DOM sink data
                        try:
                            sinks = await page.evaluate("() => window.__apex_dom_sinks || []")
                            for sink in sinks:
                                sink["page_url"] = url
                                self._dom_sinks.append(sink)
                        except Exception as e:
                            logger.debug("dom_sink_collection_failed", url=url, error=str(e))

                    except Exception as e:
                        logger.debug("crawl_page_error", url=url, error=str(e))
                        continue

                await browser.close()

        except ImportError:
            logger.warning("playwright_not_available", msg="Falling back to HTTP-only recon")
            await self._crawl_http_only(target_url, max_depth)

    async def _crawl_http_only(self, target_url: str, max_depth: int) -> None:
        """Fallback crawler using HTTP requests and BeautifulSoup."""
        from bs4 import BeautifulSoup

        urls_to_visit = [(target_url, 0)]

        while urls_to_visit and len(self._visited_urls) < 300:
            url, depth = urls_to_visit.pop(0)
            if depth > max_depth or url in self._visited_urls:
                continue

            self._visited_urls.add(url)
            response = await self._http.get(url, auth_role="scanner")
            if response is None or response.status_code >= 400:
                continue

            soup = BeautifulSoup(response.text, "html.parser")

            # Extract links
            for a_tag in soup.find_all("a", href=True):
                href = str(a_tag["href"])
                absolute = urljoin(url, href)
                parsed = urlparse(absolute)
                target_parsed = urlparse(target_url)
                if parsed.hostname and target_parsed.hostname:
                    if parsed.hostname.endswith(target_parsed.hostname):
                        urls_to_visit.append((absolute, depth + 1))

            # Extract forms
            for form in soup.find_all("form"):
                raw_action = form.get("action", url)
                action_str = raw_action if isinstance(raw_action, str) else url
                action = urljoin(url, action_str)
                raw_method = form.get("method", "GET")
                method_str = raw_method if isinstance(raw_method, str) else "GET"
                method = method_str.upper()
                inputs = []
                for inp in form.find_all(["input", "select", "textarea"]):
                    name = inp.get("name", "")
                    if name:
                        inputs.append(
                            {
                                "name": name,
                                "type": "body",
                                "input_type": inp.get("type", ""),
                            }
                        )

                self._discovered_endpoints.append(
                    Endpoint(
                        url=action,
                        method=method,
                        params=inputs,
                        headers={},
                        content_type="application/x-www-form-urlencoded",
                        requires_auth=False,
                        source="crawl_form",
                    )
                )

            # Record endpoint
            self._discovered_endpoints.append(
                Endpoint(
                    url=url,
                    method="GET",
                    params=[],
                    headers=dict(response.headers),
                    content_type=response.headers.get("content-type", ""),
                    requires_auth=False,
                    source="crawl",
                )
            )

    async def _crawl_with_katana(
        self, target_url: str, auth: Optional[Any], max_depth: int
    ) -> None:
        """Use Katana to perform a deep crawl mapping all forms, inputs, and endpoints."""
        logger.info("katana_crawl_start", target=target_url)
        try:
            import os
            import tempfile
            from src.tools.cli_wrappers import _run_command

            headers_arg = []
            if auth and auth.get("headers"):
                for k, v in auth["headers"].items():
                    headers_arg.extend(["-H", f"{k}: {v}"])
            if auth and auth.get("cookies"):
                cookie_str = "; ".join([f"{k}={v}" for k, v in auth["cookies"].items()])
                headers_arg.extend(["-H", f"Cookie: {cookie_str}"])

            with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
                out_file = tmp.name

            # Run katana
            args = [
                "katana",
                "-u",
                target_url,
                "-d",
                str(min(max_depth, 5)),  # Katana depth (5 is usually enough)
                "-jc",  # Parse JS
                "-kf",
                "all",  # Keep all fields
                "-j",  # JSON output
                "-o",
                out_file,
                "-silent",
            ] + headers_arg

            await _run_command(args, timeout=600)

            if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
                with open(out_file, "r") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        try:
                            data = json.loads(line)
                            url = data.get("request", {}).get("endpoint", "")
                            method = data.get("request", {}).get("method", "GET")

                            if not url or url in self._visited_urls:
                                continue

                            self._visited_urls.add(url)

                            # Parse parameters from URL or Body
                            params = []
                            parsed = urlparse(url)
                            if parsed.query:
                                for key, values in parse_qs(parsed.query).items():
                                    params.append(
                                        {
                                            "name": key,
                                            "value": values[0] if values else "",
                                            "type": "query",
                                        }
                                    )

                            # Record endpoint
                            self._discovered_endpoints.append(
                                Endpoint(
                                    url=url,
                                    method=method.upper(),
                                    params=params,
                                    headers={},
                                    content_type="",
                                    requires_auth=auth is not None,
                                    source="katana",
                                )
                            )
                        except Exception:
                            pass

            if os.path.exists(out_file):
                os.remove(out_file)

            logger.info("katana_crawl_complete", total_endpoints=len(self._discovered_endpoints))
        except Exception as e:
            logger.warning("katana_crawl_failed", error=str(e))

    def _fingerprint_technologies(self) -> None:
        """Fingerprint technologies from captured network data."""
        tech: dict[str, Any] = {
            "server": "",
            "framework": "",
            "language": "",
            "cms": "",
            "js_libraries": [],
            "cdn": "",
        }

        for req in self._network_requests:
            headers = req.get("headers", {})
            url = req.get("url", "")

            # Server header
            server = headers.get("server", "")
            if server:
                tech["server"] = server

            # X-Powered-By
            powered_by = headers.get("x-powered-by", "")
            if powered_by:
                tech["framework"] = powered_by

            # Detect JS libraries from URLs
            if "react" in url.lower() or "react" in str(headers):
                tech["js_libraries"].append("React")
            if "angular" in url.lower():
                tech["js_libraries"].append("Angular")
            if "vue" in url.lower():
                tech["js_libraries"].append("Vue.js")
            if "jquery" in url.lower():
                tech["js_libraries"].append("jQuery")
            if "next" in url.lower():
                tech["js_libraries"].append("Next.js")

        tech["js_libraries"] = list(set(tech["js_libraries"]))
        self._tech_fingerprint = tech
