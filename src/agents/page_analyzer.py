"""
Page Analyzer Agent (The Tactician)

AI-driven per-page security analysis. Takes the PageCapture data
(full HTML, CSS, attack surfaces, network requests, DOM sinks,
cookies, tech signals) and uses the Cloud LLM to:

  1. Assign a risk score (0-10) based on ALL captured evidence
  2. Identify specific attack vectors with target elements
  3. Decide whether this page warrants a deep scan
  4. Generate recommended tasks for the planner
  5. Flag points of interest found during analysis

This is the brain that decides "is this page worth digging into?"
vs "move on to the next page." Nothing is hardcoded - the AI
makes all decisions based on the evidence.
"""

from __future__ import annotations

import json
import time
from typing import Any

import structlog

from src.state import ApexState, PageCapture, PageAnalysis, PageNode

logger = structlog.get_logger("apexhunter.agents.page_analyzer")


ANALYZER_SYSTEM_PROMPT = """You are an elite penetration tester analyzing a web page's security posture.

You have been given the COMPLETE forensic capture of a single web page including:
- Full HTML source code
- CSS stylesheets
- All interactive elements (inputs, forms, textareas, file uploads, etc.)
- All network requests made by the page (XHR, fetch, WebSocket)
- DOM sink activity (innerHTML, eval, document.write, etc.)
- Cookies set/modified by the page
- Technology signals detected
- iframe embeds
- Meta tags and security headers from network responses

Your job is to analyze ALL of this evidence and produce a security assessment.

## Output Format (JSON only, no explanation text)
{
  "risk_score": <float 0.0 to 10.0>,
  "interest_level": "<high|medium|low|skip>",
  "reasoning": "<2-3 sentences explaining your risk assessment>",
  "attack_vectors": [
    {
      "type": "<vulnerability type, e.g. xss_reflected, sqli, csrf, idor, ssti, ssrf, open_redirect, file_upload_bypass, etc.>",
      "target_element": "<which specific input/form/parameter to target>",
      "technique": "<how to test for this - specific approach>",
      "priority": <1=critical to 5=low>,
      "description": "<what makes this element vulnerable and why>"
    }
  ],
  "recommended_tasks": [
    {
      "task_type": "<test type>",
      "target": "<specific element or endpoint>",
      "method": "<HTTP method>",
      "params": ["<param names to test>"],
      "reasoning": "<why this test should be run>"
    }
  ],
  "should_deep_scan": <true|false>,
  "deep_scan_focus": ["<area1>", "<area2>"],
  "points_of_interest": [
    {
      "type": "<finding type>",
      "detail": "<what you found>",
      "severity": "<critical|high|medium|low|info>"
    }
  ]
}

## Risk Scoring Guidelines (adapt dynamically, these are starting points):
- 9-10: Page has forms with file uploads, hidden fields with IDs, direct database interaction signals, admin functionality
- 7-8: Page has login forms, search inputs, API calls with user data, session management
- 5-6: Page has basic forms, some XHR activity, cookie manipulation
- 3-4: Page has links but minimal interactivity, some third-party scripts
- 1-2: Static content with no inputs, no interesting network activity
- 0: Completely static, no attack surface

## What makes a page worth deep scanning:
- Multiple input types (text + file + hidden fields in same form)
- API endpoints called from the page (XHR/fetch to /api/* paths)
- DOM sinks present (innerHTML, eval) with URL parameter sources
- Admin/settings/profile pages with state-changing operations
- Pages that set/modify sensitive cookies
- WebSocket connections (potential for injection)
- Forms that POST to different domains or subdomains
- Hidden fields containing tokens, IDs, or encoded data
- Pages with CSRF tokens (they protect state-changing operations)
- Third-party script inclusions that could be supply chain vectors

## What to skip:
- Pure marketing/static content pages
- Image galleries with no upload capability
- Terms of service / privacy policy pages
- 404 error pages

Be thorough but realistic. If a page has no attack surface, say so honestly.
ALWAYS output valid JSON. No markdown code blocks, no explanation text outside the JSON."""


ANALYZER_USER_TEMPLATE = """## Page Under Analysis
- URL: {url}
- Title: {title}
- Page ID: {page_id}

## Attack Surfaces Found ({surface_count} elements)
{attack_surfaces}

## Forms ({form_count} forms)
{forms}

## Network Requests ({request_count} requests)
{network_requests}

## DOM Sinks Detected ({sink_count} sinks)
{dom_sinks}

## Cookies Set/Modified ({cookie_count} cookies)
{cookies}

## Technology Signals
{tech_signals}

## Meta Tags
{meta_tags}

## Iframes ({iframe_count})
{iframes}

## WebSocket URLs ({ws_count})
{websockets}

## HTML Source (first 8000 chars)
{html_preview}

## Inline Scripts ({script_count} scripts, first 3000 chars total)
{inline_scripts}

## Context: WAF Profile
{waf_info}

## Context: Auth Roles Available
{auth_roles}

Analyze this page and produce your security assessment as JSON."""


class PageAnalyzerAgent:
    """
    The Tactician - AI-driven per-page security analysis.

    Takes a PageCapture and uses the Cloud LLM to:
    1. Score the page's risk level
    2. Identify attack vectors
    3. Decide: deep scan or move on
    4. Generate recommended tasks
    """

    def __init__(self, llm: Any):
        self._llm = llm

    async def run(self, state: ApexState) -> dict:
        """
        Analyze the current page's capture data.

        Reads from page_captures[current_page_index] and produces
        a PageAnalysis that gets added to page_analyses.
        """
        site_tree = state.get("site_tree", [])
        page_captures = state.get("page_captures", [])
        current_index = state.get("current_page_index", 0)
        existing_analyses = list(state.get("page_analyses", []))
        deep_scan_pages = list(state.get("pages_requiring_deep_scan", []))

        if current_index >= len(site_tree):
            logger.info("page_analyzer_no_more_pages")
            return {"current_phase": "page_analysis_complete"}

        page_node: PageNode = site_tree[current_index]
        page_id = page_node.get("page_id", "")
        page_url = page_node.get("url", "")

        # Skip if already analyzed
        for existing in existing_analyses:
            if existing.get("page_id") == page_id:
                logger.info("page_analyzer_already_analyzed", page_id=page_id)
                return {"current_phase": "page_analysis_cached"}

        # Find the capture for this page
        capture = None
        for cap in page_captures:
            if cap.get("page_id") == page_id:
                capture = cap
                break

        if not capture:
            logger.warning("page_analyzer_no_capture", page_id=page_id)
            # Create a minimal "skip" analysis
            skip_analysis = PageAnalysis(
                page_id=page_id,
                url=page_url,
                analyzed_at=time.time(),
                risk_score=0.0,
                interest_level="skip",
                reasoning="No capture data available for this page.",
                attack_vectors=[],
                recommended_tasks=[],
                should_deep_scan=False,
                deep_scan_focus=[],
                points_of_interest=[],
            )
            existing_analyses.append(skip_analysis)
            return {
                "page_analyses": existing_analyses,
                "current_phase": "page_analysis_complete",
            }

        logger.info(
            "page_analyzer_start",
            page_id=page_id,
            url=page_url,
            surfaces=len(capture.get("attack_surfaces", [])),
            requests=len(capture.get("network_requests", [])),
        )

        # Build the prompt with all captured data
        user_prompt = self._build_prompt(capture, state)

        # Call the LLM
        try:
            from langchain_core.messages import SystemMessage, HumanMessage

            messages = [
                SystemMessage(content=ANALYZER_SYSTEM_PROMPT),
                HumanMessage(content=user_prompt),
            ]

            response = await self._llm.ainvoke(messages)
            response_text = response.content if hasattr(response, "content") else str(response)

            # Parse the LLM's analysis
            analysis = self._parse_analysis(response_text, page_id, page_url)

        except Exception as e:
            logger.error("page_analyzer_llm_error", error=str(e), page_id=page_id)
            # Fallback: heuristic-based analysis
            analysis = self._fallback_analysis(capture, page_id, page_url)

        existing_analyses.append(analysis)

        # Track deep scan decision
        if analysis.get("should_deep_scan", False):
            if page_id not in deep_scan_pages:
                deep_scan_pages.append(page_id)
            logger.info(
                "page_analyzer_deep_scan_flagged",
                page_id=page_id,
                risk_score=analysis.get("risk_score", 0),
                focus=analysis.get("deep_scan_focus", []),
            )

        logger.info(
            "page_analyzer_complete",
            page_id=page_id,
            risk_score=analysis.get("risk_score", 0),
            interest=analysis.get("interest_level", "unknown"),
            attack_vectors=len(analysis.get("attack_vectors", [])),
            deep_scan=analysis.get("should_deep_scan", False),
        )

        return {
            "page_analyses": existing_analyses,
            "pages_requiring_deep_scan": deep_scan_pages,
            "current_phase": "page_analysis_complete",
        }

    def _build_prompt(self, capture: PageCapture, state: ApexState) -> str:
        """Build the user prompt from capture data."""
        # Attack surfaces
        surfaces = capture.get("attack_surfaces", [])
        surfaces_str = (
            json.dumps(surfaces[:30], indent=2, default=str)[:6000] if surfaces else "None found"
        )

        # Forms
        forms = capture.get("forms", [])
        forms_str = json.dumps(forms[:10], indent=2, default=str)[:4000] if forms else "None found"

        # Network requests (summarize to key fields)
        requests = capture.get("network_requests", [])
        summarized_requests = []
        for req in requests[:30]:
            summarized_requests.append(
                {
                    "url": req.get("url", ""),
                    "method": req.get("method", ""),
                    "status": req.get("response_status", 0),
                    "type": req.get("resource_type", ""),
                    "content_type": req.get("content_type", ""),
                    "is_third_party": req.get("is_third_party", False),
                    "has_body": bool(req.get("request_body", "")),
                }
            )
        requests_str = (
            json.dumps(summarized_requests, indent=2)[:5000]
            if summarized_requests
            else "None captured"
        )

        # DOM sinks
        sinks = capture.get("dom_sinks", [])
        sinks_str = (
            json.dumps(sinks[:20], indent=2, default=str)[:3000] if sinks else "None detected"
        )

        # Cookies
        cookies = capture.get("cookies_set", [])
        cookies_str = (
            json.dumps(cookies[:20], indent=2, default=str)[:2000] if cookies else "None set"
        )

        # Tech signals
        tech = capture.get("tech_signals", {})
        tech_str = json.dumps(tech, indent=2, default=str)[:2000] if tech else "None detected"

        # Meta tags
        metas = capture.get("meta_tags", {})
        meta_str = json.dumps(metas, indent=2, default=str)[:2000] if metas else "None found"

        # Iframes
        iframes = capture.get("iframes", [])
        iframe_str = json.dumps(iframes[:10], indent=2, default=str)[:1000] if iframes else "None"

        # WebSockets
        ws_urls = capture.get("websocket_urls", [])
        ws_str = json.dumps(ws_urls[:10])[:500] if ws_urls else "None"

        # HTML preview
        html = capture.get("html_content", "")
        html_preview = html[:8000] if html else "Not captured"

        # Inline scripts preview
        scripts = capture.get("inline_scripts", [])
        scripts_combined = "\n---\n".join(scripts[:5])[:3000] if scripts else "None"

        # Context
        waf = state.get("waf_profile", {})
        waf_info = f"Detected: {waf.get('detected', False)}, Name: {waf.get('waf_name', 'none')}, Rate: {waf.get('safe_request_rate', 10)}/s"

        auth_matrix = state.get("auth_matrix", [])
        auth_roles = (
            ", ".join(t.get("role", "?") for t in auth_matrix)
            if auth_matrix
            else "unauthenticated only"
        )

        return ANALYZER_USER_TEMPLATE.format(
            url=capture.get("url", ""),
            title=capture.get("page_title", ""),
            page_id=capture.get("page_id", ""),
            surface_count=len(surfaces),
            attack_surfaces=surfaces_str,
            form_count=len(forms),
            forms=forms_str,
            request_count=len(requests),
            network_requests=requests_str,
            sink_count=len(sinks),
            dom_sinks=sinks_str,
            cookie_count=len(cookies),
            cookies=cookies_str,
            tech_signals=tech_str,
            meta_tags=meta_str,
            iframe_count=len(iframes),
            iframes=iframe_str,
            ws_count=len(ws_urls),
            websockets=ws_str,
            html_preview=html_preview,
            script_count=len(scripts),
            inline_scripts=scripts_combined,
            waf_info=waf_info,
            auth_roles=auth_roles,
        )

    def _parse_analysis(self, llm_response: str, page_id: str, url: str) -> PageAnalysis:
        """Parse the LLM's JSON response into a PageAnalysis."""
        text = llm_response.strip()

        # Strip markdown code blocks if present
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0].strip()
        elif "```" in text:
            text = text.split("```")[1].split("```")[0].strip()

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Try to find JSON object in the text
            import re

            match = re.search(r"\{.*\}", text, re.DOTALL)
            if match:
                try:
                    data = json.loads(match.group())
                except json.JSONDecodeError:
                    logger.warning("page_analyzer_json_parse_failed", page_id=page_id)
                    return self._minimal_analysis(page_id, url, "LLM response was not valid JSON")
            else:
                return self._minimal_analysis(page_id, url, "No JSON found in LLM response")

        return PageAnalysis(
            page_id=page_id,
            url=url,
            analyzed_at=time.time(),
            risk_score=float(data.get("risk_score", 0.0)),
            interest_level=data.get("interest_level", "low"),
            reasoning=data.get("reasoning", ""),
            attack_vectors=data.get("attack_vectors", []),
            recommended_tasks=data.get("recommended_tasks", []),
            should_deep_scan=data.get("should_deep_scan", False),
            deep_scan_focus=data.get("deep_scan_focus", []),
            points_of_interest=data.get("points_of_interest", []),
        )

    def _fallback_analysis(self, capture: PageCapture, page_id: str, url: str) -> PageAnalysis:
        """
        Heuristic fallback when LLM is unavailable.

        Uses simple heuristics based on captured data to score the page.
        This is intentionally basic - the real intelligence comes from the LLM.
        """
        attack_surfaces = capture.get("attack_surfaces", [])
        forms = capture.get("forms", [])
        network_requests = capture.get("network_requests", [])
        dom_sinks = capture.get("dom_sinks", [])
        cookies = capture.get("cookies_set", [])
        websockets = capture.get("websocket_urls", [])

        # Simple scoring heuristic
        score = 0.0
        vectors = []
        tasks = []
        reasons = []

        # Attack surface scoring
        if len(attack_surfaces) > 0:
            score += min(len(attack_surfaces) * 0.3, 3.0)
            reasons.append(f"{len(attack_surfaces)} interactive elements")

        # Form scoring
        for form in forms:
            fields = form.get("fields", [])
            if any(f.get("type") == "password" for f in fields):
                score += 2.0
                reasons.append("Login form detected")
                vectors.append(
                    {
                        "type": "credential_testing",
                        "target_element": form.get("action", ""),
                        "technique": "Test login form for auth bypasses",
                        "priority": 2,
                        "description": "Login form with password field",
                    }
                )
            if any(f.get("type") == "file" for f in fields):
                score += 2.5
                reasons.append("File upload form")
                vectors.append(
                    {
                        "type": "file_upload_bypass",
                        "target_element": form.get("action", ""),
                        "technique": "Test file upload for extension/content-type bypass",
                        "priority": 1,
                        "description": "File upload can lead to RCE if unrestricted",
                    }
                )
            if any(f.get("type") == "hidden" for f in fields):
                score += 0.5
                reasons.append("Hidden fields present")
            if form.get("method", "").upper() == "POST":
                score += 0.5

        # XHR/fetch scoring
        xhr_requests = [r for r in network_requests if r.get("resource_type") in ("xhr", "fetch")]
        if xhr_requests:
            score += min(len(xhr_requests) * 0.5, 2.0)
            reasons.append(f"{len(xhr_requests)} API calls")

        # DOM sink scoring
        if dom_sinks:
            score += min(len(dom_sinks) * 0.5, 2.0)
            reasons.append(f"{len(dom_sinks)} DOM sinks")

        # Cookie scoring
        sensitive_cookies = [
            c for c in cookies if not c.get("httpOnly", True) or not c.get("secure", True)
        ]
        if sensitive_cookies:
            score += 1.0
            reasons.append("Cookies without HttpOnly/Secure flags")

        # WebSocket scoring
        if websockets:
            score += 1.5
            reasons.append(f"{len(websockets)} WebSocket connections")

        score = min(score, 10.0)
        interest = "skip"
        if score >= 7.0:
            interest = "high"
        elif score >= 4.0:
            interest = "medium"
        elif score >= 1.5:
            interest = "low"

        should_deep = score >= 5.0
        deep_focus = []
        if should_deep:
            if forms:
                deep_focus.append("form_testing")
            if xhr_requests:
                deep_focus.append("api_testing")
            if dom_sinks:
                deep_focus.append("dom_xss")

        return PageAnalysis(
            page_id=page_id,
            url=url,
            analyzed_at=time.time(),
            risk_score=round(score, 1),
            interest_level=interest,
            reasoning=f"Heuristic analysis (LLM fallback): {'; '.join(reasons) or 'No notable features'}",
            attack_vectors=vectors,
            recommended_tasks=tasks,
            should_deep_scan=should_deep,
            deep_scan_focus=deep_focus,
            points_of_interest=[],
        )

    def _minimal_analysis(self, page_id: str, url: str, reason: str) -> PageAnalysis:
        """Return a minimal analysis when parsing fails."""
        return PageAnalysis(
            page_id=page_id,
            url=url,
            analyzed_at=time.time(),
            risk_score=0.0,
            interest_level="low",
            reasoning=f"Analysis parsing failed: {reason}",
            attack_vectors=[],
            recommended_tasks=[],
            should_deep_scan=False,
            deep_scan_focus=[],
            points_of_interest=[],
        )
