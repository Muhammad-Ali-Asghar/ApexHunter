"""
Guarded HTTP Client

A centralized async HTTP client that routes ALL outbound requests
through the RoE Gatekeeper and Circuit Breaker before sending them.
Also records every request/response via the Flight Data Recorder.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
import structlog

from src.guardrails.roe_gatekeeper import RoEGatekeeper, RoEViolation
from src.guardrails.circuit_breaker import AdaptiveCircuitBreaker
from src.guardrails.flight_recorder import FlightDataRecorder

logger = structlog.get_logger("apexhunter.utils.http_client")


class GuardedHTTPClient:
    """
    Async HTTP client with integrated guardrails.

    Every request passes through:
    1. RoE Gatekeeper (scope validation)
    2. Circuit Breaker (health check / auto-sleep)
    3. Flight Data Recorder (WARC logging)
    """

    def __init__(
        self,
        gatekeeper: RoEGatekeeper,
        circuit_breaker: AdaptiveCircuitBreaker,
        flight_recorder: FlightDataRecorder,
        proxy_url: Optional[str] = None,
        base_delay: float = 0.5,
        timeout: float = 30.0,
    ):
        self._gatekeeper = gatekeeper
        self._breaker = circuit_breaker
        self._recorder = flight_recorder
        self._proxy_url = proxy_url
        self._base_delay = base_delay
        self._timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazily initialize the async HTTP client."""
        if self._client is None or self._client.is_closed:
            transport_kwargs = {}
            if self._proxy_url:
                transport_kwargs["proxy"] = self._proxy_url
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._timeout),
                follow_redirects=True,
                verify=False,  # Required for intercepting via mitmproxy
                **transport_kwargs,
            )
        return self._client

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        params: Optional[dict] = None,
        data: Optional[Any] = None,
        json: Optional[Any] = None,
        auth_role: str = "unknown",
        cookies: Optional[dict] = None,
    ) -> Optional[httpx.Response]:
        """
        Send a guarded HTTP request.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            url: Target URL.
            headers: Optional request headers.
            params: Optional query parameters.
            data: Optional form data body.
            json: Optional JSON body.
            auth_role: Which auth role is sending this request.
            cookies: Optional cookies dict.

        Returns:
            httpx.Response or None if blocked/failed.
        """
        # 1. RoE Gatekeeper check
        try:
            self._gatekeeper.validate_url(url)
        except RoEViolation as e:
            logger.warning("request_blocked_roe", url=url, error=str(e))
            return None

        # 2. Circuit Breaker check (may auto-sleep)
        await self._breaker.wait_if_sleeping()

        # 3. Apply pacing delay
        delay = self._breaker.get_delay(self._base_delay)
        if delay > 0:
            await asyncio.sleep(delay)

        # 4. Record the request in the Flight Data Recorder
        req_headers = headers or {}
        body_str = ""
        if data:
            body_str = str(data)
        elif json:
            import json as json_lib

            body_str = json_lib.dumps(json)

        record_id = self._recorder.record_request(
            method=method,
            url=url,
            headers=req_headers,
            body=body_str,
            auth_role=auth_role,
        )

        # 5. Send the request
        start_time = time.time()
        try:
            client = await self._get_client()
            response = await client.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data,
                json=json,
                cookies=cookies,
            )
            elapsed_ms = (time.time() - start_time) * 1000

            # 6. Record the response
            self._recorder.record_response(
                record_id=record_id,
                url=url,
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.text[:50000],  # Truncate large bodies
                response_time_ms=elapsed_ms,
            )

            # 7. Update Circuit Breaker
            self._breaker.record_request(
                status_code=response.status_code,
                response_time_ms=elapsed_ms,
            )

            logger.debug(
                "request_completed",
                method=method,
                url=url,
                status=response.status_code,
                time_ms=round(elapsed_ms, 2),
                role=auth_role,
            )

            return response

        except httpx.TimeoutException:
            elapsed_ms = (time.time() - start_time) * 1000
            self._breaker.record_request(status_code=504, response_time_ms=elapsed_ms)
            logger.warning("request_timeout", method=method, url=url)
            return None
        except httpx.ConnectError as e:
            elapsed_ms = (time.time() - start_time) * 1000
            self._breaker.record_request(status_code=502, response_time_ms=elapsed_ms)
            logger.warning(
                "request_connect_error", method=method, url=url, error=str(e)
            )
            return None
        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000
            self._breaker.record_request(status_code=500, response_time_ms=elapsed_ms)
            logger.error("request_error", method=method, url=url, error=str(e))
            return None

    async def get(self, url: str, **kwargs) -> Optional[httpx.Response]:
        """Convenience method for GET requests."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> Optional[httpx.Response]:
        """Convenience method for POST requests."""
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> Optional[httpx.Response]:
        """Convenience method for PUT requests."""
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> Optional[httpx.Response]:
        """Convenience method for DELETE requests."""
        return await self.request("DELETE", url, **kwargs)

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
