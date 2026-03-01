"""
RoE Gatekeeper (Node 0.A)

Deterministic egress firewall. Every outbound HTTP request is validated
against the target_scope regex before it leaves the container.
If the domain/IP is out of scope, the request is dropped entirely.
This prevents the AI from accidentally attacking third-party services.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse
from typing import Optional

import structlog

logger = structlog.get_logger("apexhunter.guardrails.roe_gatekeeper")


class RoEViolation(Exception):
    """Raised when a request targets an out-of-scope domain."""

    def __init__(self, url: str, scope: str):
        self.url = url
        self.scope = scope
        super().__init__(
            f"RoE VIOLATION: URL '{url}' is outside authorized scope '{scope}'. Request BLOCKED."
        )


class RoEGatekeeper:
    """
    Rules of Engagement Gatekeeper.

    Validates every outbound URL against a compiled regex pattern
    derived from the authorized target scope. Acts as a hard firewall
    that no LLM hallucination or script can bypass.

    OSINT-safe domains (Wayback Machine, CommonCrawl, OTX, etc.) are
    allowlisted because they are passive reconnaissance lookups — not
    active attacks — and must be reachable even when the target scope
    is narrow (e.g., ``localhost:3000``).
    """

    # Passive OSINT sources that are always allowed through.
    # These are read-only lookup APIs, not attack targets.
    _OSINT_SAFE_HOSTS: set[str] = {
        "web.archive.org",
        "index.commoncrawl.org",
        "data.commoncrawl.org",
        "otx.alienvault.com",
        "crt.sh",
        "api.shodan.io",
        "censys.io",
        "search.censys.io",
        "urlscan.io",
        "api.urlscan.io",
        "www.virustotal.com",
        "haveibeenpwned.com",
    }

    def __init__(self, scope_regex: str):
        """
        Args:
            scope_regex: A regex pattern matching allowed domains/IPs.
                         Example: r"^https?://(.*\\.)?example\\.com"
        """
        self._scope_pattern = re.compile(scope_regex, re.IGNORECASE)
        self._blocked_count = 0
        self._allowed_count = 0
        # Always block requests whose **host** matches these patterns
        # (cloud metadata services, link-local, etc.)
        self._always_blocked_host = [
            re.compile(r"169\.254\.169\.254", re.IGNORECASE),
            re.compile(r"metadata\.google\.internal", re.IGNORECASE),
        ]
        logger.info(
            "roe_gatekeeper_initialized",
            scope=scope_regex,
        )

    def validate_url(self, url: str) -> bool:
        """
        Validate a URL against the authorized scope.

        Args:
            url: The full URL to validate.

        Returns:
            True if the URL is within scope.

        Raises:
            RoEViolation: If the URL is outside the authorized scope.
        """
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        full_url = url.lower()

        # 1. Block cloud-metadata / link-local hosts (checked against host only)
        for pattern in self._always_blocked_host:
            if pattern.search(host):
                self._blocked_count += 1
                logger.warning(
                    "roe_blocked_dangerous",
                    url=url,
                    reason="matches always-blocked host pattern",
                )
                raise RoEViolation(url, self._scope_pattern.pattern)

        # 2. Allow known passive OSINT lookup services
        if host in self._OSINT_SAFE_HOSTS:
            self._allowed_count += 1
            logger.debug("roe_allowed_osint", url=url, host=host)
            return True

        # 3. Check against the authorized scope
        if not self._scope_pattern.search(full_url):
            self._blocked_count += 1
            logger.warning(
                "roe_blocked_out_of_scope",
                url=url,
                scope=self._scope_pattern.pattern,
            )
            raise RoEViolation(url, self._scope_pattern.pattern)

        self._allowed_count += 1
        return True

    def validate_or_skip(self, url: str) -> bool:
        """
        Validate without raising — returns False if out of scope.
        Used by agents that want to silently skip out-of-scope URLs.
        """
        try:
            return self.validate_url(url)
        except RoEViolation:
            return False

    def get_stats(self) -> dict:
        """Return gatekeeper statistics."""
        return {
            "allowed_requests": self._allowed_count,
            "blocked_requests": self._blocked_count,
            "scope_pattern": self._scope_pattern.pattern,
        }
