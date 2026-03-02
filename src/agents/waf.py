"""
WAF Detection Agent (Node 6)

Detects Web Application Firewalls by sending safe anomalous requests
and analyzing the responses. Uses LLM-driven analysis to identify WAF
products, generate evasion profiles, and determine safe request rates.
No hardcoded WAF signatures — the AI interprets response patterns.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import structlog

from src.state import ApexState, WAFProfile

logger = structlog.get_logger("apexhunter.agents.waf")

# ── Safe test payloads for WAF detection (these are intentionally
#    obvious attack strings — we WANT them to be blocked) ────────
WAF_TEST_PAYLOADS = [
    ("xss_basic", "?test=<script>alert(1)</script>"),
    ("xss_event", "?test=<img src=x onerror=alert(1)>"),
    ("sqli_basic", "?test=' OR '1'='1"),
    ("sqli_union", "?test=1 UNION SELECT 1,2,3--"),
    ("lfi_basic", "?test=../../etc/passwd"),
    ("cmdi_basic", "?test=;cat /etc/passwd"),
    ("header_overflow", None),  # Handled separately
]


class WAFAgent:
    """
    WAF Detection and Profiling Agent (AI-Driven).

    Sends safe anomalous requests to identify WAFs and uses the LLM
    to interpret response signatures, generate evasion profiles, and
    determine safe request rates. No hardcoded WAF signature database.
    """

    def __init__(self, http_client: Any, llm: Any = None):
        self._http = http_client
        self._llm = llm

    async def run(self, state: ApexState) -> dict:
        """Execute WAF detection and profiling."""
        target_url = state.get("target_url", "")

        if not target_url:
            logger.warning("waf_no_target_url")
            return {
                "waf_profile": WAFProfile(
                    detected=False,
                    waf_name="",
                    block_status_code=0,
                    block_indicators=[],
                    evasion_techniques=[],
                    safe_request_rate=10.0,
                ),
                "current_phase": "waf_skipped",
            }

        logger.info("waf_detection_start", target=target_url)

        # Phase 1: Collect raw response data from baseline and probes
        raw_evidence = await self._collect_evidence(target_url)

        # Phase 2: Try CLI tool wafw00f if available
        wafw00f_result = await self._detect_with_wafw00f(target_url)

        # Phase 3: Use LLM to analyze all evidence and produce a WAF profile
        profile = await self._analyze_with_llm(target_url, raw_evidence, wafw00f_result)

        logger.info(
            "waf_detection_complete",
            detected=profile["detected"],
            waf_name=profile["waf_name"],
            safe_rate=profile["safe_request_rate"],
        )

        return {
            "waf_profile": profile,
            "current_phase": "waf_complete",
        }

    async def _collect_evidence(self, target_url: str) -> dict:
        """
        Collect raw HTTP evidence for WAF analysis.

        Returns a dict with baseline info and probe results.
        """
        evidence: dict[str, Any] = {
            "baseline": None,
            "probes": [],
        }

        # Get baseline response
        baseline = await self._http.get(target_url, auth_role="scanner")
        if baseline is None:
            return evidence

        evidence["baseline"] = {
            "status_code": baseline.status_code,
            "headers": dict(baseline.headers),
            "body_length": len(baseline.text),
            "body_sample": baseline.text[:2000],
        }

        # Send test payloads and collect responses
        for name, payload in WAF_TEST_PAYLOADS:
            if payload is None:
                continue

            test_url = f"{target_url.rstrip('/')}/{payload}"
            response = await self._http.get(test_url, auth_role="scanner")

            if response is None:
                evidence["probes"].append(
                    {
                        "name": name,
                        "payload": payload,
                        "result": "no_response",
                    }
                )
                continue

            evidence["probes"].append(
                {
                    "name": name,
                    "payload": payload,
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body_length": len(response.text),
                    "body_sample": response.text[:2000],
                }
            )

            await asyncio.sleep(1)  # Pace between test payloads

        return evidence

    async def _detect_with_wafw00f(self, target_url: str) -> dict:
        """Try using wafw00f CLI tool for detection."""
        import shutil

        if not shutil.which("wafw00f"):
            return {}

        try:
            from src.tools.cli_wrappers import run_wafw00f

            result = await run_wafw00f(target_url)
            if result.get("detected"):
                return result
        except Exception as e:
            logger.debug("wafw00f_error", error=str(e))

        return {}

    async def _analyze_with_llm(
        self,
        target_url: str,
        evidence: dict,
        wafw00f_result: dict,
    ) -> WAFProfile:
        """
        Use the LLM to analyze collected HTTP evidence and determine:
        - Whether a WAF is present
        - Which WAF product it is
        - What evasion techniques to use
        - What the safe request rate is
        """
        if not self._llm:
            # Fallback: heuristic analysis without LLM
            return self._heuristic_analysis(evidence, wafw00f_result)

        # Build the analysis prompt
        prompt = f"""You are a web application security expert specializing in WAF detection
and evasion. Analyze the following HTTP evidence collected from probing
{target_url} and determine if a Web Application Firewall is present.

## Baseline Response
{json.dumps(evidence.get("baseline", {}), indent=2, default=str)[:3000]}

## Probe Results
{json.dumps(evidence.get("probes", []), indent=2, default=str)[:5000]}

## wafw00f Result
{json.dumps(wafw00f_result, indent=2, default=str) if wafw00f_result else "wafw00f not available or returned no results."}

## Your Task
Analyze ALL the evidence: response headers, status codes, body content,
behavioral differences between baseline and probes, and any WAF-specific
indicators (e.g., cf-ray for Cloudflare, x-sucuri-id for Sucuri, etc.).

Return a JSON object with these fields:
{{
    "detected": true/false,
    "waf_name": "name of WAF or empty string",
    "confidence": 0.0-1.0,
    "block_status_code": integer (the HTTP status code used for blocking, 0 if none),
    "block_indicators": ["list", "of", "blocking", "patterns", "found"],
    "evasion_techniques": ["list", "of", "recommended", "evasion", "techniques"],
    "safe_request_rate": float (requests per second that won't trigger rate limiting),
    "reasoning": "brief explanation of your analysis"
}}

For evasion_techniques, be specific and actionable. Examples:
- "url_encode_payloads" - URL-encode attack payloads
- "double_url_encode" - Double URL-encode to bypass single-decode filters
- "unicode_normalization" - Use Unicode characters that normalize to ASCII
- "case_variation" - Mix upper/lowercase in SQL keywords
- "comment_injection_sql" - Insert SQL comments between keywords
- "chunked_transfer_encoding" - Use chunked TE to split payloads
- "slow_request_pacing" - Send requests very slowly
- "randomize_user_agent" - Rotate user agents
- "fragment_payloads" - Split payloads across multiple parameters

For safe_request_rate: aggressive WAFs (Cloudflare, Akamai) need 1-2 req/s,
moderate (AWS WAF, ModSecurity) allow 3-5 req/s, no WAF allows 10+ req/s.

Return ONLY the JSON object, no explanation outside the JSON."""

        try:
            from langchain_core.messages import HumanMessage

            response = await self._llm.ainvoke([HumanMessage(content=prompt)])
            text = response.content.strip()

            # Extract JSON from response
            if "```" in text:
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            text = text.strip()

            result = json.loads(text)

            logger.info(
                "waf_llm_analysis_complete",
                detected=result.get("detected", False),
                waf_name=result.get("waf_name", ""),
                confidence=result.get("confidence", 0),
                reasoning=result.get("reasoning", "")[:200],
            )

            return WAFProfile(
                detected=bool(result.get("detected", False)),
                waf_name=result.get("waf_name", ""),
                block_status_code=int(result.get("block_status_code", 0)),
                block_indicators=result.get("block_indicators", []),
                evasion_techniques=result.get("evasion_techniques", []),
                safe_request_rate=float(result.get("safe_request_rate", 10.0)),
            )

        except Exception as e:
            logger.warning("waf_llm_analysis_failed", error=str(e))
            return self._heuristic_analysis(evidence, wafw00f_result)

    def _heuristic_analysis(self, evidence: dict, wafw00f_result: dict) -> WAFProfile:
        """
        Fallback heuristic analysis when LLM is unavailable.

        Checks for obvious blocking behavior (403/429 on probes vs 200 on baseline)
        without relying on any hardcoded WAF signature database.
        """
        detected = False
        waf_name = wafw00f_result.get("waf_name", "")
        block_status = 0
        indicators: list[str] = []

        if wafw00f_result.get("detected"):
            detected = True

        baseline = evidence.get("baseline")
        if not baseline:
            return WAFProfile(
                detected=detected,
                waf_name=waf_name,
                block_status_code=block_status,
                block_indicators=indicators,
                evasion_techniques=["url_encode_payloads", "randomize_user_agent", "pace_requests"],
                safe_request_rate=5.0 if detected else 10.0,
            )

        baseline_status = baseline.get("status_code", 200)

        # Check if probes are being blocked (behavioral detection)
        blocked_count = 0
        for probe in evidence.get("probes", []):
            status = probe.get("status_code", 0)
            if status in (403, 406, 429, 501, 503) and baseline_status not in (
                403,
                406,
                429,
                501,
                503,
            ):
                blocked_count += 1
                block_status = status

            # Check for significant response size difference
            body_len = probe.get("body_length", 0)
            if abs(body_len - baseline.get("body_length", 0)) > 1000 and status != baseline_status:
                blocked_count += 1

        if blocked_count >= 2:
            detected = True
            if not waf_name:
                waf_name = "unknown"

        # Basic evasion recommendations based on whether blocking was detected
        evasion = ["url_encode_payloads", "randomize_user_agent", "pace_requests"]
        if detected:
            evasion.extend(["double_url_encode", "case_variation", "chunked_transfer_encoding"])

        # Conservative rate if WAF detected
        rate = 2.0 if detected else 10.0

        return WAFProfile(
            detected=detected,
            waf_name=waf_name,
            block_status_code=block_status,
            block_indicators=indicators,
            evasion_techniques=evasion,
            safe_request_rate=rate,
        )
