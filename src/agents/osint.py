"""
OSINT Agent (Node 2 - The Ghost Node)

Queries historical data sources (Wayback Machine, CommonCrawl, AlienVault OTX)
to extract deprecated endpoints, forgotten parameters, and old JavaScript files.
Implements strict retry-with-backoff logic as per the blueprint.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urlparse, urljoin

import structlog
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

from src.state import ApexState, Endpoint

logger = structlog.get_logger("apexhunter.agents.osint")


class OSINTAgent:
    """
    The Ghost Node — mines historical data to find forgotten attack surface.

    Queries:
    - Wayback Machine CDX API for archived URLs
    - CommonCrawl Index for historical crawl data
    - AlienVault OTX for threat intelligence on the domain
    """

    def __init__(
        self, http_client: Any, max_retries: int = 3, retry_backoff: float = 5.0
    ):
        self._http = http_client
        self._max_retries = max_retries
        self._retry_backoff = retry_backoff

    async def run(self, state: ApexState) -> dict:
        """
        Execute the OSINT reconnaissance phase.

        Returns:
            Dict with updated state fields.
        """
        target_url = state["target_url"]
        parsed = urlparse(target_url)
        domain = parsed.netloc

        logger.info("osint_start", domain=domain)

        historical_data: list[dict[str, Any]] = []
        hidden_endpoints: list[Endpoint] = []

        # Run all OSINT sources concurrently
        results = await asyncio.gather(
            self._query_wayback(domain),
            self._query_commoncrawl(domain),
            self._query_otx(domain),
            return_exceptions=True,
        )

        wayback_urls: list[str] = (
            results[0] if not isinstance(results[0], BaseException) else []
        )
        commoncrawl_urls: list[str] = (
            results[1] if not isinstance(results[1], BaseException) else []
        )
        otx_data: dict = results[2] if not isinstance(results[2], BaseException) else {}

        if isinstance(results[0], BaseException):
            logger.warning("osint_wayback_failed", error=str(results[0]))
        if isinstance(results[1], BaseException):
            logger.warning("osint_commoncrawl_failed", error=str(results[1]))
        if isinstance(results[2], BaseException):
            logger.warning("osint_otx_failed", error=str(results[2]))

        # Deduplicate and normalize URLs
        all_urls = set()
        for url in wayback_urls + commoncrawl_urls:
            # Normalize: strip fragments, lowercase
            normalized = url.split("#")[0].split("?")[0].lower()
            all_urls.add(url)

        # Convert to Endpoint objects
        for url in all_urls:
            parsed_url = urlparse(url)
            endpoint = Endpoint(
                url=url,
                method="GET",
                params=[],
                headers={},
                content_type="",
                requires_auth=False,
                source="osint",
            )

            # Extract query parameters
            if parsed_url.query:
                params = []
                for pair in parsed_url.query.split("&"):
                    if "=" in pair:
                        key, val = pair.split("=", 1)
                        params.append({"name": key, "value": val, "type": "query"})
                endpoint["params"] = params

            hidden_endpoints.append(endpoint)

        # Store historical context
        historical_data.append(
            {
                "source": "wayback",
                "urls_found": len(wayback_urls),
                "sample_urls": wayback_urls[:20],
            }
        )
        historical_data.append(
            {
                "source": "commoncrawl",
                "urls_found": len(commoncrawl_urls),
                "sample_urls": commoncrawl_urls[:20],
            }
        )
        if otx_data:
            historical_data.append(
                {
                    "source": "otx",
                    "data": otx_data,
                }
            )

        logger.info(
            "osint_complete",
            total_historical_urls=len(all_urls),
            endpoints_extracted=len(hidden_endpoints),
        )

        return {
            "historical_osint_data": historical_data,
            "hidden_surface_map": hidden_endpoints,
        }

    async def _query_with_retry(self, coro_func, *args, **kwargs) -> Any:
        """Execute a coroutine with retry logic."""
        last_error = None
        for attempt in range(1, self._max_retries + 1):
            try:
                return await coro_func(*args, **kwargs)
            except Exception as e:
                last_error = e
                wait_time = self._retry_backoff * attempt
                logger.warning(
                    "osint_retry",
                    source=coro_func.__name__,
                    attempt=attempt,
                    max_retries=self._max_retries,
                    wait=wait_time,
                    error=str(e),
                )
                await asyncio.sleep(wait_time)
        raise last_error  # type: ignore

    async def _query_wayback(self, domain: str) -> list[str]:
        """Query the Wayback Machine CDX API for archived URLs."""
        return await self._query_with_retry(self._wayback_impl, domain)

    async def _wayback_impl(self, domain: str) -> list[str]:
        """Implementation of Wayback Machine query."""
        url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url={domain}/*&output=json&fl=original&collapse=urlkey&limit=5000"
        )
        response = await self._http.get(url)
        if response is None or response.status_code != 200:
            raise ConnectionError(
                f"Wayback Machine returned {response.status_code if response else 'None'}"
            )

        try:
            data = response.json()
            # First row is headers, rest are URLs
            if isinstance(data, list) and len(data) > 1:
                urls = [row[0] for row in data[1:] if isinstance(row, list) and row]
                logger.info("wayback_results", count=len(urls))
                return urls
        except Exception:
            pass

        return []

    async def _query_commoncrawl(self, domain: str) -> list[str]:
        """Query CommonCrawl Index for historical crawl data."""
        return await self._query_with_retry(self._commoncrawl_impl, domain)

    async def _commoncrawl_impl(self, domain: str) -> list[str]:
        """Implementation of CommonCrawl query."""
        # Get the latest index
        index_url = "https://index.commoncrawl.org/collinfo.json"
        response = await self._http.get(index_url)
        if response is None or response.status_code != 200:
            raise ConnectionError("CommonCrawl index unavailable")

        indexes = response.json()
        if not indexes:
            return []

        # Query the latest index
        latest = indexes[0]
        cdx_api = latest.get("cdx-api", "")
        if not cdx_api:
            return []

        search_url = f"{cdx_api}?url={domain}/*&output=json&limit=2000"
        response = await self._http.get(search_url)
        if response is None or response.status_code != 200:
            return []

        urls = []
        for line in response.text.strip().split("\n"):
            try:
                import json

                entry = json.loads(line)
                if "url" in entry:
                    urls.append(entry["url"])
            except Exception:
                continue

        logger.info("commoncrawl_results", count=len(urls))
        return urls

    async def _query_otx(self, domain: str) -> dict:
        """Query AlienVault OTX for threat intelligence."""
        return await self._query_with_retry(self._otx_impl, domain)

    async def _otx_impl(self, domain: str) -> dict:
        """Implementation of AlienVault OTX query."""
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
        response = await self._http.get(url)
        if response is None or response.status_code != 200:
            raise ConnectionError("OTX unavailable")

        data = response.json()
        result = {
            "has_pulses": data.get("has_next", False),
            "url_list": [],
        }

        for entry in data.get("url_list", [])[:100]:
            result["url_list"].append(
                {
                    "url": entry.get("url", ""),
                    "date": entry.get("date", ""),
                    "httpcode": entry.get("httpcode", 0),
                }
            )

        logger.info("otx_results", urls=len(result["url_list"]))
        return result
