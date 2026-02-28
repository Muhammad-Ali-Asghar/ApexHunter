"""
WAF Detection Agent (Node 6)

Detects Web Application Firewalls by sending safe anomalous requests
and analyzing the responses. Generates an evasion profile that
subsequent nodes use to pace and encode their payloads.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

import structlog

from src.state import ApexState, WAFProfile

logger = structlog.get_logger("apexhunter.agents.waf")

# ── Known WAF signatures ─────────────────────────────────
WAF_SIGNATURES = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "__cfduid"],
        "body_patterns": ["cloudflare", "attention required", "cf-error"],
        "server": ["cloudflare"],
    },
    "aws_waf": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id"],
        "body_patterns": ["awselb", "aws", "amazonwebservices"],
        "server": ["awselb", "amazons3"],
    },
    "akamai": {
        "headers": ["x-akamai-transformed", "akamai-grn"],
        "body_patterns": ["akamai", "access denied", "reference#"],
        "server": ["akamaighost", "akamai"],
    },
    "imperva": {
        "headers": ["x-iinfo", "x-cdn"],
        "body_patterns": ["incapsula", "imperva", "request unsuccessful"],
        "server": [],
    },
    "modsecurity": {
        "headers": [],
        "body_patterns": ["modsecurity", "mod_security", "noyb"],
        "server": [],
    },
    "sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "body_patterns": ["sucuri", "access denied - sucuri"],
        "server": ["sucuri"],
    },
    "f5_bigip": {
        "headers": ["x-wa-info"],
        "body_patterns": ["the requested url was rejected"],
        "server": ["bigip"],
    },
    "fortiweb": {
        "headers": [],
        "body_patterns": ["fortigate", "fortiweb"],
        "server": ["fortiweb"],
    },
}

# ── Safe test payloads for WAF detection ──────────────────
WAF_TEST_PAYLOADS = [
    # XSS-like
    ("xss_basic", "?test=<script>alert(1)</script>"),
    ("xss_event", "?test=<img src=x onerror=alert(1)>"),
    # SQLi-like
    ("sqli_basic", "?test=' OR '1'='1"),
    ("sqli_union", "?test=1 UNION SELECT 1,2,3--"),
    # Path traversal
    ("lfi_basic", "?test=../../etc/passwd"),
    # Command injection
    ("cmdi_basic", "?test=;cat /etc/passwd"),
    # Oversized header
    ("header_overflow", None),  # Handled separately
]


class WAFAgent:
    """
    WAF Detection and Profiling Agent.

    Sends safe anomalous requests to identify WAFs and generates
    an evasion profile (pacing, encoding techniques).
    """

    def __init__(self, http_client: Any):
        self._http = http_client

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

        # Phase 1: Check response headers for WAF signatures
        waf_name = await self._detect_from_headers(target_url)

        # Phase 2: Try CLI tool wafw00f if available
        if not waf_name:
            waf_name = await self._detect_with_wafw00f(target_url)

        # Phase 3: Send test payloads and analyze blocking behavior
        block_info = await self._detect_from_payloads(target_url)

        # Build the WAF profile
        detected = bool(waf_name) or block_info.get("blocked", False)
        if not waf_name and block_info.get("blocked"):
            waf_name = "unknown"

        profile = WAFProfile(
            detected=detected,
            waf_name=waf_name or "",
            block_status_code=block_info.get("block_status", 0),
            block_indicators=block_info.get("indicators", []),
            evasion_techniques=self._generate_evasion_techniques(waf_name or ""),
            safe_request_rate=self._calculate_safe_rate(waf_name or ""),
        )

        logger.info(
            "waf_detection_complete",
            detected=detected,
            waf_name=waf_name,
            safe_rate=profile["safe_request_rate"],
        )

        return {
            "waf_profile": profile,
            "current_phase": "waf_complete",
        }

    async def _detect_from_headers(self, target_url: str) -> str:
        """Analyze response headers for WAF signatures."""
        response = await self._http.get(target_url, auth_role="scanner")
        if response is None:
            return ""

        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        server = headers.get("server", "")

        for waf_name, signatures in WAF_SIGNATURES.items():
            # Check headers
            for sig_header in signatures["headers"]:
                if sig_header.lower() in headers:
                    logger.info("waf_detected_header", waf=waf_name, header=sig_header)
                    return waf_name

            # Check server header
            for srv in signatures["server"]:
                if srv.lower() in server:
                    logger.info("waf_detected_server", waf=waf_name, server=server)
                    return waf_name

        return ""

    async def _detect_with_wafw00f(self, target_url: str) -> str:
        """Try using wafw00f CLI tool for detection."""
        import shutil

        if not shutil.which("wafw00f"):
            return ""

        try:
            from src.tools.cli_wrappers import run_wafw00f

            result = await run_wafw00f(target_url)
            if result.get("detected"):
                return result.get("waf_name", "unknown")
        except Exception as e:
            logger.debug("wafw00f_error", error=str(e))

        return ""

    async def _detect_from_payloads(self, target_url: str) -> dict:
        """Send test payloads and analyze blocking behavior."""
        block_info = {
            "blocked": False,
            "block_status": 0,
            "indicators": [],
        }

        # First get a baseline response
        baseline = await self._http.get(target_url, auth_role="scanner")
        if baseline is None:
            return block_info

        baseline_status = baseline.status_code
        baseline_length = len(baseline.text)

        for name, payload in WAF_TEST_PAYLOADS:
            if payload is None:
                continue

            test_url = f"{target_url.rstrip('/')}/{payload}"
            response = await self._http.get(test_url, auth_role="scanner")
            if response is None:
                continue

            # Check if the response indicates blocking
            status = response.status_code
            body = response.text.lower()

            if status in (403, 406, 429, 501, 503):
                block_info["blocked"] = True
                block_info["block_status"] = status

                # Extract blocking indicators
                for waf_name, sigs in WAF_SIGNATURES.items():
                    for pattern in sigs["body_patterns"]:
                        if pattern in body:
                            block_info["indicators"].append(pattern)

                logger.info(
                    "waf_payload_blocked",
                    payload_name=name,
                    status=status,
                )
                break

            # Check for significant response change (redirect to captcha, etc.)
            if abs(len(response.text) - baseline_length) > 1000 and status != baseline_status:
                block_info["blocked"] = True
                block_info["block_status"] = status

            await asyncio.sleep(1)  # Pace between test payloads

        return block_info

    def _generate_evasion_techniques(self, waf_name: str) -> list[str]:
        """Generate evasion techniques based on the detected WAF."""
        techniques = [
            "url_encode_payloads",
            "randomize_user_agent",
            "pace_requests",
        ]

        if waf_name == "cloudflare":
            techniques.extend(
                [
                    "double_url_encode",
                    "unicode_normalization",
                    "chunked_transfer_encoding",
                    "vary_content_type",
                ]
            )
        elif waf_name == "aws_waf":
            techniques.extend(
                [
                    "case_variation",
                    "comment_injection_sql",
                    "header_manipulation",
                ]
            )
        elif waf_name == "modsecurity":
            techniques.extend(
                [
                    "null_byte_injection",
                    "multipart_boundary_manipulation",
                    "http_parameter_pollution",
                ]
            )
        elif waf_name == "akamai":
            techniques.extend(
                [
                    "slow_request_pacing",
                    "fragment_payloads",
                    "alternate_encodings",
                ]
            )

        return techniques

    def _calculate_safe_rate(self, waf_name: str) -> float:
        """Calculate a safe request rate based on the WAF type."""
        rates = {
            "cloudflare": 2.0,
            "aws_waf": 5.0,
            "akamai": 1.0,
            "imperva": 3.0,
            "modsecurity": 5.0,
            "sucuri": 2.0,
            "f5_bigip": 3.0,
            "fortiweb": 3.0,
            "unknown": 2.0,
        }
        return rates.get(waf_name, 10.0)
