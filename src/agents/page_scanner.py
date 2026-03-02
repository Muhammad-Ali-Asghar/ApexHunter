"""
Page Scanner Agent (The Forensic Lens)

Performs deep per-page capture for a single page:
  1. Full HTML source capture
  2. All CSS (inline + external stylesheets)
  3. All scripts (inline + external) with content previews
  4. Complete attack surface discovery (forms, inputs, textareas,
     selects, buttons, file uploads, hidden fields, contenteditable)
  5. Network request/response interception (XHR, fetch, WS, etc.)
  6. DOM sink monitoring (innerHTML, eval, document.write, etc.)
  7. Cookie tracking (set/modified by this page)
  8. Technology signal extraction from page-level evidence

This agent operates on ONE page at a time and is called in a loop
by the graph orchestrator for each page in the site tree.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Any, Optional
from urllib.parse import urlparse, urljoin

import structlog

from src.state import (
    ApexState,
    PageNode,
    PageCapture,
    AttackSurface,
    NetworkCapture,
)

logger = structlog.get_logger("apexhunter.agents.page_scanner")


# ── JavaScript injection snippets for Playwright ──────────────

# Extracts all interactive elements (attack surfaces) from the page
ATTACK_SURFACE_JS = """() => {
    const surfaces = [];

    function getXPath(el) {
        if (!el || el.nodeType !== 1) return '';
        const parts = [];
        while (el && el.nodeType === 1) {
            let idx = 1;
            let sib = el.previousSibling;
            while (sib) {
                if (sib.nodeType === 1 && sib.tagName === el.tagName) idx++;
                sib = sib.previousSibling;
            }
            parts.unshift(el.tagName.toLowerCase() + '[' + idx + ']');
            el = el.parentNode;
        }
        return '/' + parts.join('/');
    }

    function getDataAttributes(el) {
        const data = {};
        for (const attr of el.attributes) {
            if (attr.name.startsWith('data-')) {
                data[attr.name] = attr.value;
            }
        }
        return data;
    }

    function getEventHandlers(el) {
        const handlers = [];
        const eventAttrs = [
            'onclick', 'onsubmit', 'onchange', 'oninput', 'onfocus',
            'onblur', 'onkeyup', 'onkeydown', 'onkeypress', 'onmouseover',
            'onload', 'onerror', 'onmouseenter', 'onmouseleave'
        ];
        for (const attr of eventAttrs) {
            if (el.hasAttribute(attr)) {
                handlers.push(attr + '=' + (el.getAttribute(attr) || '').substring(0, 200));
            }
        }
        return handlers;
    }

    function getParentFormId(el) {
        const form = el.closest('form');
        return form ? (form.id || form.name || form.action || 'anonymous_form') : '';
    }

    // All input elements
    document.querySelectorAll('input').forEach(el => {
        surfaces.push({
            element_type: 'input',
            element_id: el.id || '',
            element_name: el.name || '',
            element_class: el.className || '',
            input_type: el.type || 'text',
            form_action: el.form ? el.form.action : '',
            form_method: el.form ? (el.form.method || 'GET').toUpperCase() : '',
            placeholder: el.placeholder || '',
            max_length: el.maxLength > 0 ? el.maxLength : null,
            pattern: el.pattern || '',
            accepts: el.accept || '',
            autocomplete: el.autocomplete || '',
            is_required: el.required,
            current_value: el.value ? el.value.substring(0, 100) : '',
            aria_label: el.getAttribute('aria-label') || '',
            data_attributes: getDataAttributes(el),
            event_handlers: getEventHandlers(el),
            parent_form_id: getParentFormId(el),
            xpath: getXPath(el)
        });
    });

    // Textareas
    document.querySelectorAll('textarea').forEach(el => {
        surfaces.push({
            element_type: 'textarea',
            element_id: el.id || '',
            element_name: el.name || '',
            element_class: el.className || '',
            input_type: '',
            form_action: el.form ? el.form.action : '',
            form_method: el.form ? (el.form.method || 'GET').toUpperCase() : '',
            placeholder: el.placeholder || '',
            max_length: el.maxLength > 0 ? el.maxLength : null,
            pattern: '',
            accepts: '',
            autocomplete: '',
            is_required: el.required,
            current_value: el.value ? el.value.substring(0, 100) : '',
            aria_label: el.getAttribute('aria-label') || '',
            data_attributes: getDataAttributes(el),
            event_handlers: getEventHandlers(el),
            parent_form_id: getParentFormId(el),
            xpath: getXPath(el)
        });
    });

    // Select dropdowns
    document.querySelectorAll('select').forEach(el => {
        const options = Array.from(el.options || []).map(o => o.value).join(',');
        surfaces.push({
            element_type: 'select',
            element_id: el.id || '',
            element_name: el.name || '',
            element_class: el.className || '',
            input_type: '',
            form_action: el.form ? el.form.action : '',
            form_method: el.form ? (el.form.method || 'GET').toUpperCase() : '',
            placeholder: '',
            max_length: null,
            pattern: '',
            accepts: '',
            autocomplete: '',
            is_required: el.required,
            current_value: options.substring(0, 200),
            aria_label: el.getAttribute('aria-label') || '',
            data_attributes: getDataAttributes(el),
            event_handlers: getEventHandlers(el),
            parent_form_id: getParentFormId(el),
            xpath: getXPath(el)
        });
    });

    // File upload inputs (special attention)
    document.querySelectorAll('input[type="file"]').forEach(el => {
        // Already captured above, but mark specifically
    });

    // Hidden fields (often contain CSRF tokens, IDs, etc.)
    document.querySelectorAll('input[type="hidden"]').forEach(el => {
        // Already captured above as input type="hidden"
    });

    // Contenteditable elements
    document.querySelectorAll('[contenteditable="true"]').forEach(el => {
        surfaces.push({
            element_type: 'contenteditable',
            element_id: el.id || '',
            element_name: el.getAttribute('name') || '',
            element_class: el.className || '',
            input_type: '',
            form_action: '',
            form_method: '',
            placeholder: el.getAttribute('placeholder') || '',
            max_length: null,
            pattern: '',
            accepts: '',
            autocomplete: '',
            is_required: false,
            current_value: (el.textContent || '').substring(0, 100),
            aria_label: el.getAttribute('aria-label') || '',
            data_attributes: getDataAttributes(el),
            event_handlers: getEventHandlers(el),
            parent_form_id: '',
            xpath: getXPath(el)
        });
    });

    // Buttons (especially those with onclick or form submission)
    document.querySelectorAll('button, input[type="submit"], input[type="button"]').forEach(el => {
        if (el.tagName === 'BUTTON' || el.type === 'submit' || el.type === 'button') {
            surfaces.push({
                element_type: 'button',
                element_id: el.id || '',
                element_name: el.name || '',
                element_class: el.className || '',
                input_type: el.type || 'button',
                form_action: el.form ? el.form.action : '',
                form_method: el.form ? (el.form.method || 'GET').toUpperCase() : '',
                placeholder: '',
                max_length: null,
                pattern: '',
                accepts: '',
                autocomplete: '',
                is_required: false,
                current_value: (el.textContent || el.value || '').substring(0, 100),
                aria_label: el.getAttribute('aria-label') || '',
                data_attributes: getDataAttributes(el),
                event_handlers: getEventHandlers(el),
                parent_form_id: getParentFormId(el),
                xpath: getXPath(el)
            });
        }
    });

    return surfaces;
}"""

# Extracts detailed form structures
FORM_EXTRACTION_JS = """() => {
    const forms = [];
    document.querySelectorAll('form').forEach(form => {
        const fields = [];
        form.querySelectorAll('input, textarea, select, button').forEach(el => {
            fields.push({
                tag: el.tagName.toLowerCase(),
                type: el.type || '',
                name: el.name || '',
                id: el.id || '',
                value: (el.value || '').substring(0, 100),
                placeholder: el.placeholder || '',
                required: el.required || false,
                pattern: el.pattern || '',
                maxlength: el.maxLength > 0 ? el.maxLength : null,
                autocomplete: el.autocomplete || '',
                accept: el.accept || '',
                disabled: el.disabled || false,
                readonly: el.readOnly || false,
            });
        });

        forms.push({
            action: form.action || window.location.href,
            method: (form.method || 'GET').toUpperCase(),
            enctype: form.enctype || '',
            id: form.id || '',
            name: form.name || '',
            target: form.target || '',
            novalidate: form.noValidate || false,
            autocomplete: form.autocomplete || '',
            fields: fields,
            field_count: fields.length,
        });
    });
    return forms;
}"""

# Extracts all links with metadata
LINK_EXTRACTION_JS = """() => {
    const links = [];
    document.querySelectorAll('a[href]').forEach(a => {
        links.push({
            href: a.href,
            text: (a.textContent || '').trim().substring(0, 100),
            rel: a.rel || '',
            target: a.target || '',
        });
    });
    return links;
}"""

# Extracts iframe information
IFRAME_EXTRACTION_JS = """() => {
    const iframes = [];
    document.querySelectorAll('iframe, frame').forEach(f => {
        iframes.push({
            src: f.src || '',
            sandbox: f.sandbox ? f.sandbox.value : '',
            name: f.name || '',
            allow: f.allow || '',
        });
    });
    return iframes;
}"""

# Extracts meta tags
META_EXTRACTION_JS = """() => {
    const metas = {};
    document.querySelectorAll('meta').forEach(m => {
        const name = m.name || m.httpEquiv || m.getAttribute('property') || '';
        if (name) {
            metas[name] = m.content || '';
        }
    });
    return metas;
}"""

# Extracts inline scripts
INLINE_SCRIPTS_JS = """() => {
    const scripts = [];
    document.querySelectorAll('script:not([src])').forEach(s => {
        const content = s.textContent || '';
        if (content.trim().length > 0) {
            scripts.push(content.substring(0, 5000));
        }
    });
    return scripts;
}"""

# Extracts external script references
EXTERNAL_SCRIPTS_JS = """() => {
    const scripts = [];
    document.querySelectorAll('script[src]').forEach(s => {
        scripts.push({
            url: s.src,
            async: s.async || false,
            defer: s.defer || false,
            type: s.type || '',
            integrity: s.integrity || '',
            crossorigin: s.crossOrigin || '',
        });
    });
    return scripts;
}"""

# Extracts CSS stylesheet links
CSS_EXTRACTION_JS = """() => {
    const styles = [];
    // External stylesheets
    document.querySelectorAll('link[rel="stylesheet"]').forEach(l => {
        styles.push({
            url: l.href,
            media: l.media || '',
            type: 'external',
        });
    });
    // Inline styles
    document.querySelectorAll('style').forEach(s => {
        const content = s.textContent || '';
        if (content.trim().length > 0) {
            styles.push({
                url: '',
                content: content.substring(0, 3000),
                type: 'inline',
            });
        }
    });
    return styles;
}"""

# DOM sink monitoring - detects dangerous operations
DOM_SINK_MONITOR_JS = """() => {
    const sinks = [];
    const html = document.documentElement.outerHTML;

    // Check for dangerous patterns in inline scripts
    const dangerousPatterns = [
        {pattern: 'innerHTML', type: 'dom_xss_sink'},
        {pattern: 'outerHTML', type: 'dom_xss_sink'},
        {pattern: 'document.write', type: 'dom_xss_sink'},
        {pattern: 'document.writeln', type: 'dom_xss_sink'},
        {pattern: 'eval(', type: 'code_execution_sink'},
        {pattern: 'setTimeout(', type: 'code_execution_sink'},
        {pattern: 'setInterval(', type: 'code_execution_sink'},
        {pattern: 'Function(', type: 'code_execution_sink'},
        {pattern: 'location.href', type: 'redirect_sink'},
        {pattern: 'location.assign', type: 'redirect_sink'},
        {pattern: 'location.replace', type: 'redirect_sink'},
        {pattern: 'window.open', type: 'redirect_sink'},
        {pattern: '.src =', type: 'resource_injection_sink'},
        {pattern: 'postMessage', type: 'message_sink'},
        {pattern: 'localStorage', type: 'storage_sink'},
        {pattern: 'sessionStorage', type: 'storage_sink'},
        {pattern: 'document.cookie', type: 'cookie_sink'},
        {pattern: 'fetch(', type: 'network_sink'},
        {pattern: 'XMLHttpRequest', type: 'network_sink'},
        {pattern: 'WebSocket', type: 'websocket_sink'},
    ];

    document.querySelectorAll('script:not([src])').forEach(script => {
        const content = script.textContent || '';
        for (const dp of dangerousPatterns) {
            if (content.includes(dp.pattern)) {
                // Get a context snippet around the pattern
                const idx = content.indexOf(dp.pattern);
                const start = Math.max(0, idx - 50);
                const end = Math.min(content.length, idx + dp.pattern.length + 100);
                sinks.push({
                    type: dp.type,
                    pattern: dp.pattern,
                    context: content.substring(start, end).trim(),
                    location: 'inline_script',
                });
            }
        }
    });

    // Check for URL-sourced data flowing into sinks
    const urlParams = new URLSearchParams(window.location.search);
    const hash = window.location.hash;
    if (urlParams.toString() || hash) {
        sinks.push({
            type: 'url_input_source',
            pattern: 'URL parameters or hash present',
            context: 'params=' + urlParams.toString().substring(0, 200) + ' hash=' + hash.substring(0, 100),
            location: 'url',
        });
    }

    return sinks;
}"""

# Technology signal extraction from page content
TECH_SIGNALS_JS = """() => {
    const signals = {};

    // Generator meta tag
    const gen = document.querySelector('meta[name="generator"]');
    if (gen) signals.generator = gen.content;

    // Detect frontend frameworks from DOM
    if (document.querySelector('[ng-app], [ng-controller], [ng-model]'))
        signals.angular_1 = true;
    if (document.querySelector('[_nghost], [_ngcontent], [ng-version]'))
        signals.angular_2plus = true;
    if (document.querySelector('[data-reactroot], [data-reactid]'))
        signals.react = true;
    if (document.querySelector('[data-v-], [data-vue]'))
        signals.vue = true;
    if (document.querySelector('[data-ember-view], [data-ember-action]'))
        signals.ember = true;
    if (document.querySelector('[data-svelte], .svelte-'))
        signals.svelte = true;

    // Check for common libraries
    if (window.jQuery || window.$) signals.jquery = true;
    if (window.angular) signals.angular = true;
    if (window.React || window.__REACT_DEVTOOLS_GLOBAL_HOOK__) signals.react = true;
    if (window.__VUE__) signals.vue = true;
    if (window.Backbone) signals.backbone = true;
    if (window.Ember) signals.ember = true;

    // Check for common CMS indicators
    if (document.querySelector('meta[name="generator"][content*="WordPress"]'))
        signals.wordpress = true;
    if (document.querySelector('link[href*="wp-content"]'))
        signals.wordpress = true;
    if (document.querySelector('meta[name="generator"][content*="Drupal"]'))
        signals.drupal = true;
    if (document.querySelector('meta[name="generator"][content*="Joomla"]'))
        signals.joomla = true;

    // CSRF token detection
    const csrfInputs = document.querySelectorAll(
        'input[name*="csrf"], input[name*="token"], input[name*="_token"], ' +
        'input[name*="authenticity_token"], meta[name*="csrf"]'
    );
    if (csrfInputs.length > 0) {
        signals.csrf_protection = true;
        signals.csrf_token_names = Array.from(csrfInputs).map(
            el => el.name || el.getAttribute('name') || el.getAttribute('content') || ''
        ).filter(Boolean);
    }

    // Check page for API patterns
    const pageContent = document.body ? document.body.textContent : '';
    if (pageContent.includes('GraphQL') || document.querySelector('[class*="graphql"]'))
        signals.graphql = true;

    return signals;
}"""


class PageScannerAgent:
    """
    The Forensic Lens - deep per-page DOM + network capture.

    For each page in the site tree, this agent:
    1. Opens the page in Playwright with network interception
    2. Captures complete HTML, CSS, scripts
    3. Discovers all attack surfaces (interactive elements)
    4. Records all network requests/responses
    5. Monitors for dangerous DOM sinks
    6. Tracks cookies set/modified
    7. Extracts technology signals

    Falls back to HTTP-only capture when Playwright is unavailable.
    """

    def __init__(self, http_client: Any, config: Any):
        self._http = http_client
        self._config = config

    async def run(self, state: ApexState) -> dict:
        """
        Scan the current page (determined by current_page_index).

        Returns a PageCapture object merged into the state's page_captures list.
        """
        site_tree = state.get("site_tree", [])
        current_index = state.get("current_page_index", 0)
        auth_matrix = state.get("auth_matrix", [])
        existing_captures = list(state.get("page_captures", []))

        if current_index >= len(site_tree):
            logger.info("page_scanner_no_more_pages", index=current_index)
            return {"current_phase": "page_scan_complete"}

        page_node: PageNode = site_tree[current_index]
        page_url = page_node.get("url", "")
        page_id = page_node.get("page_id", "")

        if not page_url:
            logger.warning("page_scanner_empty_url", page_id=page_id)
            return {"current_phase": "page_scan_skipped"}

        # Skip if already captured
        for existing in existing_captures:
            if existing.get("page_id") == page_id:
                logger.info("page_scanner_already_captured", page_id=page_id)
                return {"current_phase": "page_scan_cached"}

        logger.info(
            "page_scanner_start",
            page_id=page_id,
            url=page_url,
            index=current_index,
            total=len(site_tree),
        )

        primary_auth = auth_matrix[0] if auth_matrix else None

        try:
            capture = await self._scan_with_playwright(page_url, page_id, primary_auth)
        except ImportError:
            logger.warning("playwright_unavailable_for_scanner", msg="Falling back to HTTP-only")
            capture = await self._scan_http_only(page_url, page_id)

        existing_captures.append(capture)

        logger.info(
            "page_scanner_complete",
            page_id=page_id,
            attack_surfaces=len(capture.get("attack_surfaces", [])),
            network_requests=len(capture.get("network_requests", [])),
            dom_sinks=len(capture.get("dom_sinks", [])),
            forms=len(capture.get("forms", [])),
        )

        return {
            "page_captures": existing_captures,
            "current_phase": "page_scan_complete",
        }

    async def _scan_with_playwright(
        self, url: str, page_id: str, auth: Optional[Any]
    ) -> PageCapture:
        """Deep scan using Playwright with full network interception."""
        from playwright.async_api import async_playwright

        captured_requests: list[NetworkCapture] = []
        websocket_urls: list[str] = []
        cookies_before: dict[str, str] = {}
        cookies_after: dict[str, str] = {}

        target_host = urlparse(url).hostname or ""

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 720},
            )

            # Set auth cookies
            if auth and auth.get("cookies"):
                parsed = urlparse(url)
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

            # ── Network interception ──────────────────────────
            def on_request(request):
                """Capture outgoing requests."""
                try:
                    req_url = request.url
                    req_parsed = urlparse(req_url)
                    is_third_party = (
                        req_parsed.hostname != target_host if req_parsed.hostname else False
                    )

                    captured_requests.append(
                        NetworkCapture(
                            url=req_url,
                            method=request.method,
                            request_headers=dict(request.headers) if request.headers else {},
                            request_body=(request.post_data or "")[:2000],
                            response_status=0,  # Will be updated on response
                            response_headers={},
                            response_body_preview="",
                            response_size=0,
                            content_type="",
                            resource_type=request.resource_type or "other",
                            timing_ms=0,
                            is_third_party=is_third_party,
                            initiator="",
                            direction="outgoing",
                        )
                    )
                except Exception:
                    pass

            def on_response(response):
                """Update captured requests with response data."""
                try:
                    resp_url = response.url
                    for capture in reversed(captured_requests):
                        if capture.get("url") == resp_url and capture.get("response_status") == 0:
                            capture["response_status"] = response.status
                            capture["response_headers"] = (
                                dict(response.headers) if response.headers else {}
                            )
                            capture["content_type"] = response.headers.get("content-type", "")
                            try:
                                size = response.headers.get("content-length", "0")
                                capture["response_size"] = int(size)
                            except (ValueError, TypeError):
                                pass
                            break
                except Exception:
                    pass

            def on_websocket(ws):
                """Track WebSocket connections."""
                websocket_urls.append(ws.url)

            page.on("request", on_request)
            page.on("response", on_response)
            page.on("websocket", on_websocket)

            # ── Capture cookies before navigation ─────────────
            pre_cookies = await context.cookies()
            cookies_before = {c["name"]: c["value"] for c in pre_cookies}

            # ── Navigate to page ──────────────────────────────
            start_time = time.time()
            try:
                response = await page.goto(url, wait_until="networkidle", timeout=20000)
            except Exception as e:
                logger.warning("page_scanner_nav_error", url=url, error=str(e))
                # Try with domcontentloaded instead
                try:
                    response = await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                except Exception:
                    await browser.close()
                    return self._empty_capture(page_id, url)

            nav_time = (time.time() - start_time) * 1000

            # Wait a bit for async JS to settle
            await asyncio.sleep(1.5)

            # ── Capture cookies after navigation ──────────────
            post_cookies = await context.cookies()
            cookies_after = {c["name"]: c["value"] for c in post_cookies}

            # Identify cookies set/modified by this page
            cookies_set = []
            for cookie in post_cookies:
                name = cookie["name"]
                if name not in cookies_before or cookies_before[name] != cookie["value"]:
                    cookies_set.append(
                        {
                            "name": name,
                            "value": cookie["value"][:100],
                            "domain": cookie.get("domain", ""),
                            "path": cookie.get("path", "/"),
                            "secure": cookie.get("secure", False),
                            "httpOnly": cookie.get("httpOnly", False),
                            "sameSite": cookie.get("sameSite", "None"),
                            "expires": cookie.get("expires", -1),
                        }
                    )

            # ── Extract page content ──────────────────────────
            html_content = ""
            try:
                html_content = await page.content()
            except Exception:
                pass

            page_title = ""
            try:
                page_title = await page.title()
            except Exception:
                pass

            # ── Execute all extraction scripts ────────────────
            attack_surfaces = await self._safe_evaluate(page, ATTACK_SURFACE_JS, [])
            forms = await self._safe_evaluate(page, FORM_EXTRACTION_JS, [])
            links = await self._safe_evaluate(page, LINK_EXTRACTION_JS, [])
            iframes = await self._safe_evaluate(page, IFRAME_EXTRACTION_JS, [])
            meta_tags = await self._safe_evaluate(page, META_EXTRACTION_JS, {})
            inline_scripts = await self._safe_evaluate(page, INLINE_SCRIPTS_JS, [])
            external_scripts = await self._safe_evaluate(page, EXTERNAL_SCRIPTS_JS, [])
            css_data = await self._safe_evaluate(page, CSS_EXTRACTION_JS, [])
            dom_sinks = await self._safe_evaluate(page, DOM_SINK_MONITOR_JS, [])
            tech_signals = await self._safe_evaluate(page, TECH_SIGNALS_JS, {})

            # ── Fetch response body previews for key XHR/fetch requests ──
            await self._enrich_network_captures(captured_requests)

            await browser.close()

        # ── Build the PageCapture ─────────────────────────────
        # Convert raw attack surface dicts to AttackSurface TypedDicts
        typed_surfaces = [self._dict_to_attack_surface(s) for s in attack_surfaces]

        # Build CSS content list
        css_content = []
        for css in css_data:
            entry = {"url": css.get("url", ""), "type": css.get("type", "external")}
            if css.get("content"):
                entry["content"] = css["content"]
            css_content.append(entry)

        # Build external scripts list with content_preview
        ext_scripts = []
        for script in external_scripts:
            ext_scripts.append(
                {
                    "url": script.get("url", ""),
                    "content_preview": "",
                    "async": script.get("async", False),
                    "defer": script.get("defer", False),
                    "integrity": script.get("integrity", ""),
                }
            )

        capture = PageCapture(
            page_id=page_id,
            url=url,
            captured_at=time.time(),
            html_content=html_content[:100000],  # Cap at 100KB
            css_content=css_content,
            inline_scripts=inline_scripts[:50],  # Cap at 50 scripts
            external_scripts=ext_scripts,
            meta_tags=meta_tags,
            page_title=page_title,
            attack_surfaces=typed_surfaces,
            forms=forms,
            links=links[:500],  # Cap at 500 links
            iframes=iframes,
            websocket_urls=websocket_urls,
            network_requests=captured_requests,
            dom_sinks=dom_sinks,
            cookies_set=cookies_set,
            tech_signals=tech_signals,
        )

        return capture

    async def _scan_http_only(self, url: str, page_id: str) -> PageCapture:
        """Fallback: HTTP-only scan using requests + BeautifulSoup."""
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            logger.error("beautifulsoup_not_available")
            return self._empty_capture(page_id, url)

        response = await self._http.get(url, auth_role="scanner")
        if response is None:
            return self._empty_capture(page_id, url)

        soup = BeautifulSoup(response.text, "html.parser")
        html_content = response.text

        # Extract attack surfaces
        attack_surfaces: list[AttackSurface] = []

        # Inputs
        for el in soup.find_all("input"):
            attack_surfaces.append(
                AttackSurface(
                    element_type="input",
                    element_id=el.get("id", ""),
                    element_name=el.get("name", ""),
                    element_class=el.get("class", [""])[0] if el.get("class") else "",
                    input_type=el.get("type", "text"),
                    form_action=el.find_parent("form").get("action", "")
                    if el.find_parent("form")
                    else "",
                    form_method=(
                        el.find_parent("form").get("method", "GET")
                        if el.find_parent("form")
                        else ""
                    ).upper(),
                    placeholder=el.get("placeholder", ""),
                    max_length=int(el.get("maxlength", 0)) or None,
                    pattern=el.get("pattern", ""),
                    accepts=el.get("accept", ""),
                    autocomplete=el.get("autocomplete", ""),
                    is_required=el.has_attr("required"),
                    current_value=el.get("value", "")[:100],
                    aria_label=el.get("aria-label", ""),
                    data_attributes={k: v for k, v in el.attrs.items() if k.startswith("data-")},
                    event_handlers=[f"{k}={v}" for k, v in el.attrs.items() if k.startswith("on")],
                    parent_form_id=el.find_parent("form").get("id", "")
                    if el.find_parent("form")
                    else "",
                    xpath="",
                )
            )

        # Textareas
        for el in soup.find_all("textarea"):
            attack_surfaces.append(
                AttackSurface(
                    element_type="textarea",
                    element_id=el.get("id", ""),
                    element_name=el.get("name", ""),
                    element_class=el.get("class", [""])[0] if el.get("class") else "",
                    input_type="",
                    form_action=el.find_parent("form").get("action", "")
                    if el.find_parent("form")
                    else "",
                    form_method=(
                        el.find_parent("form").get("method", "GET")
                        if el.find_parent("form")
                        else ""
                    ).upper(),
                    placeholder=el.get("placeholder", ""),
                    max_length=int(el.get("maxlength", 0)) or None,
                    pattern="",
                    accepts="",
                    autocomplete="",
                    is_required=el.has_attr("required"),
                    current_value=(el.string or "")[:100],
                    aria_label=el.get("aria-label", ""),
                    data_attributes={k: v for k, v in el.attrs.items() if k.startswith("data-")},
                    event_handlers=[f"{k}={v}" for k, v in el.attrs.items() if k.startswith("on")],
                    parent_form_id=el.find_parent("form").get("id", "")
                    if el.find_parent("form")
                    else "",
                    xpath="",
                )
            )

        # Forms
        forms = []
        for form in soup.find_all("form"):
            fields = []
            for field in form.find_all(["input", "textarea", "select", "button"]):
                fields.append(
                    {
                        "tag": field.name,
                        "type": field.get("type", ""),
                        "name": field.get("name", ""),
                        "id": field.get("id", ""),
                        "value": (field.get("value", "") or "")[:100],
                        "placeholder": field.get("placeholder", ""),
                        "required": field.has_attr("required"),
                    }
                )

            raw_action = form.get("action", url)
            action_str = raw_action if isinstance(raw_action, str) else url
            raw_method = form.get("method", "GET")
            method_str = raw_method if isinstance(raw_method, str) else "GET"

            forms.append(
                {
                    "action": urljoin(url, action_str),
                    "method": method_str.upper(),
                    "enctype": form.get("enctype", ""),
                    "id": form.get("id", ""),
                    "name": form.get("name", ""),
                    "fields": fields,
                    "field_count": len(fields),
                }
            )

        # Links
        links = []
        for a in soup.find_all("a", href=True):
            links.append(
                {
                    "href": urljoin(url, str(a["href"])),
                    "text": (a.get_text(strip=True) or "")[:100],
                    "rel": a.get("rel", [""])[0] if a.get("rel") else "",
                    "target": a.get("target", ""),
                }
            )

        # Iframes
        iframes = []
        for iframe in soup.find_all(["iframe", "frame"]):
            iframes.append(
                {
                    "src": iframe.get("src", ""),
                    "sandbox": iframe.get("sandbox", ""),
                }
            )

        # Meta tags
        meta_tags = {}
        for meta in soup.find_all("meta"):
            name = meta.get("name") or meta.get("http-equiv") or meta.get("property") or ""
            if name:
                meta_tags[name] = meta.get("content", "")

        # Inline scripts
        inline_scripts = []
        for script in soup.find_all("script"):
            if not script.get("src") and script.string:
                inline_scripts.append(script.string[:5000])

        # External scripts
        external_scripts = []
        for script in soup.find_all("script", src=True):
            external_scripts.append(
                {
                    "url": urljoin(url, script["src"]),
                    "content_preview": "",
                }
            )

        # CSS
        css_content = []
        for link in soup.find_all("link", rel="stylesheet"):
            css_content.append(
                {
                    "url": urljoin(url, link.get("href", "")),
                    "type": "external",
                }
            )
        for style in soup.find_all("style"):
            if style.string:
                css_content.append(
                    {
                        "url": "",
                        "content": style.string[:3000],
                        "type": "inline",
                    }
                )

        page_title = soup.title.string if soup.title else ""

        # Network capture: just record the main page request
        network_requests = [
            NetworkCapture(
                url=url,
                method="GET",
                request_headers={},
                request_body="",
                response_status=response.status_code,
                response_headers=dict(response.headers),
                response_body_preview=response.text[:2000],
                response_size=len(response.text),
                content_type=response.headers.get("content-type", ""),
                resource_type="document",
                timing_ms=0,
                is_third_party=False,
                initiator="direct",
                direction="outgoing",
            )
        ]

        return PageCapture(
            page_id=page_id,
            url=url,
            captured_at=time.time(),
            html_content=html_content[:100000],
            css_content=css_content,
            inline_scripts=inline_scripts[:50],
            external_scripts=external_scripts,
            meta_tags=meta_tags,
            page_title=page_title or "",
            attack_surfaces=attack_surfaces,
            forms=forms,
            links=links[:500],
            iframes=iframes,
            websocket_urls=[],
            network_requests=network_requests,
            dom_sinks=[],  # Cannot detect DOM sinks without JS execution
            cookies_set=[],
            tech_signals={},
        )

    # ── Helpers ────────────────────────────────────────────

    async def _safe_evaluate(self, page: Any, js_code: str, default: Any) -> Any:
        """Safely evaluate JavaScript on a page, returning default on failure."""
        try:
            result = await page.evaluate(js_code)
            return result if result is not None else default
        except Exception as e:
            logger.debug("page_scanner_js_eval_error", error=str(e)[:200])
            return default

    async def _enrich_network_captures(self, captures: list[NetworkCapture]) -> None:
        """
        Try to fetch response body previews for important XHR/fetch requests.
        We only do this for non-image, non-font, small resources.
        """
        important_types = {"xhr", "fetch", "document", "other"}
        for capture in captures:
            if (
                capture.get("resource_type") in important_types
                and capture.get("response_status", 0) in range(200, 400)
                and capture.get("response_size", 0) < 50000
                and not capture.get("response_body_preview")
            ):
                # We already have headers; body preview would require
                # intercepting in route handler (more complex). For now
                # we note that body was not captured inline.
                pass

    def _dict_to_attack_surface(self, d: dict) -> AttackSurface:
        """Convert a raw dict from JS evaluation to an AttackSurface TypedDict."""
        return AttackSurface(
            element_type=d.get("element_type", ""),
            element_id=d.get("element_id", ""),
            element_name=d.get("element_name", ""),
            element_class=d.get("element_class", ""),
            input_type=d.get("input_type", ""),
            form_action=d.get("form_action", ""),
            form_method=d.get("form_method", ""),
            placeholder=d.get("placeholder", ""),
            max_length=d.get("max_length"),
            pattern=d.get("pattern", ""),
            accepts=d.get("accepts", ""),
            autocomplete=d.get("autocomplete", ""),
            is_required=d.get("is_required", False),
            current_value=d.get("current_value", ""),
            aria_label=d.get("aria_label", ""),
            data_attributes=d.get("data_attributes", {}),
            event_handlers=d.get("event_handlers", []),
            parent_form_id=d.get("parent_form_id", ""),
            xpath=d.get("xpath", ""),
        )

    def _empty_capture(self, page_id: str, url: str) -> PageCapture:
        """Return an empty PageCapture for pages that couldn't be scanned."""
        return PageCapture(
            page_id=page_id,
            url=url,
            captured_at=time.time(),
            html_content="",
            css_content=[],
            inline_scripts=[],
            external_scripts=[],
            meta_tags={},
            page_title="",
            attack_surfaces=[],
            forms=[],
            links=[],
            iframes=[],
            websocket_urls=[],
            network_requests=[],
            dom_sinks=[],
            cookies_set=[],
            tech_signals={},
        )
