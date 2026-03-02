"""
Site Crawler Agent (New Phase 1 - The Cartographer)

Crawls the entire web application to build a tree-like structure
mapping all pages. For each page, discovers attack surfaces
(input boxes, forms, interactive elements). Does NOT perform
deep DOM capture yet - that happens in the Page Scanner.

This replaces the bulk crawling approach with a structured
site mapping that feeds the page-by-page analysis loop.
"""

from __future__ import annotations

import asyncio
import json
import uuid
import time
from typing import Any, Optional
from urllib.parse import urlparse, urljoin, parse_qs
from collections import defaultdict

import structlog

from src.state import ApexState, PageNode, Endpoint

logger = structlog.get_logger("apexhunter.agents.crawler")


class SiteCrawlerAgent:
    """
    The Cartographer - builds a complete site tree.

    1. Crawls the entire application via Playwright (SPA-aware)
    2. Builds a hierarchical tree of all discovered pages
    3. Records basic page metadata (status, content-type, title)
    4. Discovers child links, form actions, JS navigations
    5. Merges with OSINT-discovered endpoints
    6. Falls back to HTTP-only crawling if Playwright unavailable
    """

    def __init__(self, http_client: Any, config: Any):
        self._http = http_client
        self._config = config
        self._visited_urls: set[str] = set()
        self._page_nodes: dict[str, PageNode] = {}  # url -> PageNode
        self._url_to_id: dict[str, str] = {}  # url -> page_id
        self._discovered_endpoints: list[Endpoint] = []
        self._api_schemas: list[dict] = []

    async def run(self, state: ApexState) -> dict:
        """Execute the site crawling phase to build the page tree."""
        target_url = state.get("target_url", "")
        auth_matrix = state.get("auth_matrix", [])
        max_depth = self._config.target.max_depth if self._config else 10
        osint_endpoints = list(state.get("hidden_surface_map", []))

        if not target_url:
            logger.error("crawler_no_target_url")
            return {"current_phase": "crawl_skipped"}

        logger.info("crawler_start", target=target_url, max_depth=max_depth)

        # Phase 1: Hunt for API schemas first (they inform structure)
        await self._hunt_api_schemas(target_url)

        # Phase 2: Crawl the site to discover all pages
        primary_auth = auth_matrix[0] if auth_matrix else None
        await self._crawl_site(target_url, primary_auth, max_depth)

        # Phase 3: Integrate OSINT endpoints into the tree
        self._integrate_osint_endpoints(osint_endpoints, target_url)

        # Phase 4: Build parent-child relationships (the tree)
        site_tree = self._build_tree(target_url)

        # Convert internal endpoints list
        all_endpoints = self._discovered_endpoints

        logger.info(
            "crawler_complete",
            total_pages=len(site_tree),
            total_endpoints=len(all_endpoints),
            api_schemas=len(self._api_schemas),
            tree_depth=max((n.get("depth", 0) for n in site_tree), default=0),
        )

        return {
            "site_tree": site_tree,
            "discovered_endpoints": all_endpoints,
            "openapi_schemas": self._api_schemas,
            "current_page_index": 0,
            "pages_completed": [],
            "current_phase": "crawl_complete",
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
                continue
            if isinstance(result, dict) and result.get("found"):
                self._api_schemas.append(result)
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

            if "graphql" in url.lower() or "graphiql" in url.lower():
                logger.info("graphql_endpoint_found", url=url)
                return {"found": True, "url": url, "schema": None, "type": "graphql"}

        return {"found": False, "url": url}

    def _parse_openapi_schema(self, schema: dict, base_url: str) -> None:
        """Parse an OpenAPI/Swagger schema into Endpoint objects."""
        paths = schema.get("paths", {})

        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() not in ("get", "post", "put", "delete", "patch", "options"):
                    continue

                url = urljoin(base_url, path)
                params = []

                for param in details.get("parameters", []):
                    params.append(
                        {
                            "name": param.get("name", ""),
                            "type": param.get("in", "query"),
                            "required": param.get("required", False),
                            "schema": param.get("schema", {}),
                        }
                    )

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

                # Also register the API endpoint as a page node
                self._register_page(
                    url=url,
                    status_code=200,
                    content_type="application/json",
                    title=f"API: {method.upper()} {path}",
                    discovered_via="openapi",
                    depth=1,
                )

    async def _crawl_site(self, target_url: str, auth: Optional[Any], max_depth: int) -> None:
        """Crawl the target using Playwright to discover all pages."""
        try:
            from playwright.async_api import async_playwright

            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    ignore_https_errors=True,
                    viewport={"width": 1280, "height": 720},
                )

                # Set auth cookies
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

                # BFS crawl
                urls_to_visit = [(target_url, 0, None)]  # (url, depth, parent_url)

                while urls_to_visit and len(self._visited_urls) < 500:
                    url, depth, parent_url = urls_to_visit.pop(0)

                    if depth > max_depth:
                        continue

                    # Normalize URL
                    url_no_hash = url.split("#")[0]
                    if url_no_hash in self._visited_urls:
                        continue

                    # Scope check
                    parsed = urlparse(url)
                    target_parsed = urlparse(target_url)
                    if parsed.hostname and target_parsed.hostname:
                        if not parsed.hostname.endswith(target_parsed.hostname):
                            continue

                    # Skip static assets
                    if url.lower().endswith(
                        (
                            ".jpg",
                            ".jpeg",
                            ".png",
                            ".gif",
                            ".css",
                            ".woff2",
                            ".ttf",
                            ".svg",
                            ".ico",
                            ".mp4",
                            ".mp3",
                            ".pdf",
                            ".zip",
                            ".gz",
                            ".tar",
                        )
                    ):
                        continue

                    self._visited_urls.add(url_no_hash)

                    try:
                        logger.info("crawler_visiting", url=url, depth=depth)
                        response = await page.goto(url, wait_until="networkidle", timeout=15000)
                        if not response:
                            continue

                        # Get page title
                        title = ""
                        try:
                            title = await page.title()
                        except Exception:
                            pass

                        # Register this page in the tree
                        page_id = self._register_page(
                            url=url_no_hash,
                            status_code=response.status,
                            content_type=response.headers.get("content-type", ""),
                            title=title,
                            discovered_via="crawl",
                            depth=depth,
                            parent_url=parent_url,
                            response_headers=dict(response.headers) if response.headers else {},
                        )

                        # Record as endpoint
                        parsed_url = urlparse(url)
                        params_list = []
                        if parsed_url.query:
                            for key, values in parse_qs(parsed_url.query).items():
                                params_list.append(
                                    {
                                        "name": key,
                                        "value": values[0] if values else "",
                                        "type": "query",
                                    }
                                )

                        self._discovered_endpoints.append(
                            Endpoint(
                                url=url_no_hash,
                                method="GET",
                                params=params_list,
                                headers=dict(response.headers) if response.headers else {},
                                content_type=response.headers.get("content-type", "")
                                if response.headers
                                else "",
                                requires_auth=False,
                                source="crawl",
                            )
                        )

                        # Extract all links, forms, and navigable elements
                        discovered = await page.evaluate("""() => {
                            const result = {links: [], forms: [], js_links: []};

                            // All anchor links
                            document.querySelectorAll('a[href]').forEach(a => {
                                result.links.push({
                                    href: a.href,
                                    text: (a.textContent || '').trim().substring(0, 100),
                                    rel: a.rel || '',
                                });
                            });

                            // All forms with their action URLs
                            document.querySelectorAll('form').forEach(form => {
                                const inputs = [];
                                form.querySelectorAll('input,select,textarea,button').forEach(el => {
                                    inputs.push({
                                        tag: el.tagName.toLowerCase(),
                                        name: el.name || '',
                                        type: el.type || '',
                                        id: el.id || '',
                                        placeholder: el.placeholder || '',
                                        required: el.required || false,
                                    });
                                });
                                result.forms.push({
                                    action: form.action || window.location.href,
                                    method: (form.method || 'GET').toUpperCase(),
                                    inputs: inputs,
                                    id: form.id || '',
                                    name: form.name || '',
                                });
                            });

                            // JavaScript-driven navigation (onclick handlers with URLs)
                            document.querySelectorAll('[onclick]').forEach(el => {
                                const onclick = el.getAttribute('onclick') || '';
                                const urlMatch = onclick.match(/(?:window\\.location|location\\.href|navigate).*?['\\"](.*?)['\\"]/);
                                if (urlMatch) {
                                    result.js_links.push(urlMatch[1]);
                                }
                            });

                            // Router links (React/Angular/Vue)
                            document.querySelectorAll('[routerlink], [ng-href], [to]').forEach(el => {
                                const link = el.getAttribute('routerlink') || el.getAttribute('ng-href') || el.getAttribute('to');
                                if (link) result.js_links.push(link);
                            });

                            return result;
                        }""")

                        # Process discovered links
                        for link_info in discovered.get("links", []):
                            href = link_info.get("href", "")
                            if href and not href.startswith(
                                ("javascript:", "mailto:", "tel:", "data:")
                            ):
                                absolute = urljoin(url, href)
                                if not absolute.lower().endswith(
                                    (
                                        ".jpg",
                                        ".jpeg",
                                        ".png",
                                        ".gif",
                                        ".css",
                                        ".woff2",
                                        ".ttf",
                                        ".svg",
                                        ".ico",
                                    )
                                ):
                                    urls_to_visit.append((absolute, depth + 1, url_no_hash))

                        # Process forms as both endpoints and navigation targets
                        for form_info in discovered.get("forms", []):
                            form_action = form_info.get("action", url)
                            form_method = form_info.get("method", "GET")
                            form_inputs = form_info.get("inputs", [])

                            # Register form action as a page/endpoint
                            form_params = [
                                {
                                    "name": inp["name"],
                                    "type": "body" if form_method == "POST" else "query",
                                    "input_type": inp.get("type", ""),
                                }
                                for inp in form_inputs
                                if inp.get("name")
                            ]

                            self._discovered_endpoints.append(
                                Endpoint(
                                    url=form_action,
                                    method=form_method,
                                    params=form_params,
                                    headers={},
                                    content_type="application/x-www-form-urlencoded",
                                    requires_auth=False,
                                    source="crawl_form",
                                )
                            )

                            # Add form target as a page to visit
                            if form_method == "GET":
                                urls_to_visit.append((form_action, depth + 1, url_no_hash))

                        # Process JS navigation links
                        for js_link in discovered.get("js_links", []):
                            absolute = urljoin(url, js_link)
                            urls_to_visit.append((absolute, depth + 1, url_no_hash))

                    except Exception as e:
                        logger.debug("crawler_page_error", url=url, error=str(e))
                        continue

                await browser.close()

        except ImportError:
            logger.warning("playwright_not_available", msg="Falling back to HTTP-only crawl")
            await self._crawl_http_only(target_url, max_depth)

    async def _crawl_http_only(self, target_url: str, max_depth: int) -> None:
        """Fallback crawler using HTTP requests and BeautifulSoup."""
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            logger.error("beautifulsoup_not_available")
            return

        urls_to_visit = [(target_url, 0, None)]

        while urls_to_visit and len(self._visited_urls) < 300:
            url, depth, parent_url = urls_to_visit.pop(0)
            url_no_hash = url.split("#")[0]

            if depth > max_depth or url_no_hash in self._visited_urls:
                continue

            self._visited_urls.add(url_no_hash)
            logger.info("crawler_http_visiting", url=url, depth=depth)

            response = await self._http.get(url, auth_role="scanner")
            if response is None or response.status_code >= 404:
                continue

            soup = BeautifulSoup(response.text, "html.parser")
            title = soup.title.string if soup.title else ""

            # Register page
            self._register_page(
                url=url_no_hash,
                status_code=response.status_code,
                content_type=response.headers.get("content-type", ""),
                title=title or "",
                discovered_via="crawl",
                depth=depth,
                parent_url=parent_url,
                response_headers=dict(response.headers),
            )

            # Record endpoint
            self._discovered_endpoints.append(
                Endpoint(
                    url=url_no_hash,
                    method="GET",
                    params=[],
                    headers=dict(response.headers),
                    content_type=response.headers.get("content-type", ""),
                    requires_auth=False,
                    source="crawl",
                )
            )

            # Extract links
            for a_tag in soup.find_all("a", href=True):
                href = str(a_tag["href"])
                if href.startswith(("javascript:", "mailto:", "tel:")):
                    continue
                absolute = urljoin(url, href)
                parsed = urlparse(absolute)
                target_parsed = urlparse(target_url)
                if parsed.hostname and target_parsed.hostname:
                    if parsed.hostname.endswith(target_parsed.hostname):
                        urls_to_visit.append((absolute, depth + 1, url_no_hash))

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
                                "type": "body" if method == "POST" else "query",
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

    def _register_page(
        self,
        url: str,
        status_code: int,
        content_type: str,
        title: str,
        discovered_via: str,
        depth: int,
        parent_url: Optional[str] = None,
        response_headers: Optional[dict] = None,
    ) -> str:
        """Register a discovered page in the tree. Returns the page_id."""
        if url in self._url_to_id:
            return self._url_to_id[url]

        page_id = f"page-{uuid.uuid4().hex[:8]}"
        parsed = urlparse(url)

        parent_id = None
        if parent_url and parent_url in self._url_to_id:
            parent_id = self._url_to_id[parent_url]
            # Add this as a child of the parent
            parent_node = self._page_nodes.get(parent_url)
            if parent_node:
                children = list(parent_node.get("children_ids", []))
                children.append(page_id)
                parent_node["children_ids"] = children

        node = PageNode(
            page_id=page_id,
            url=url,
            path=parsed.path or "/",
            title=title,
            depth=depth,
            parent_id=parent_id,
            children_ids=[],
            status_code=status_code,
            content_type=content_type,
            response_headers=response_headers or {},
            discovered_via=discovered_via,
        )

        self._page_nodes[url] = node
        self._url_to_id[url] = page_id
        return page_id

    def _integrate_osint_endpoints(self, osint_endpoints: list[Endpoint], target_url: str) -> None:
        """Integrate OSINT-discovered endpoints into the site tree."""
        for ep in osint_endpoints:
            url = ep.get("url", "")
            if not url or url in self._url_to_id:
                continue

            # Only add if same domain
            parsed = urlparse(url)
            target_parsed = urlparse(target_url)
            if parsed.hostname and target_parsed.hostname:
                if not parsed.hostname.endswith(target_parsed.hostname):
                    continue

            self._register_page(
                url=url,
                status_code=0,  # Unknown - not yet verified
                content_type="",
                title="",
                discovered_via="osint",
                depth=1,  # OSINT endpoints are considered depth 1
            )
            self._discovered_endpoints.append(ep)

    def _build_tree(self, target_url: str) -> list[PageNode]:
        """Build the final ordered tree structure from discovered pages."""
        # Sort by depth (BFS order), then by URL for deterministic ordering
        nodes = sorted(
            self._page_nodes.values(),
            key=lambda n: (n.get("depth", 0), n.get("url", "")),
        )

        # Prioritize pages that are more likely to have attack surfaces:
        # 1. Pages with forms/inputs (discovered via crawl_form)
        # 2. API endpoints
        # 3. Pages with query parameters
        # 4. Admin/dashboard pages
        # 5. Regular pages
        def priority_score(node: PageNode) -> int:
            url = node.get("url", "").lower()
            path = node.get("path", "").lower()
            score = 0

            # API endpoints are high priority
            if "api" in path or node.get("content_type", "").startswith("application/json"):
                score -= 10

            # Admin/auth pages
            if any(
                kw in path
                for kw in [
                    "admin",
                    "login",
                    "auth",
                    "dashboard",
                    "manage",
                    "settings",
                    "user",
                    "account",
                    "profile",
                ]
            ):
                score -= 8

            # Pages with parameters in URL
            if "?" in url:
                score -= 5

            # Form submission endpoints
            if node.get("discovered_via") == "crawl_form":
                score -= 7

            # OSINT-discovered (potentially forgotten/legacy)
            if node.get("discovered_via") == "osint":
                score -= 3

            return score

        nodes.sort(key=priority_score)

        logger.info(
            "site_tree_built",
            total_pages=len(nodes),
            max_depth=max((n.get("depth", 0) for n in nodes), default=0),
            root=target_url,
        )

        return nodes
