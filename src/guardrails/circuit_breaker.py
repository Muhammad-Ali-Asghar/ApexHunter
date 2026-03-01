"""
Adaptive Circuit Breaker (Node 0.B)

Continuously monitors the health of the target application.
If the 5xx error rate spikes or latency degrades severely,
it triggers an "Auto-Sleep": pauses the LangGraph for a set
duration, verifies health, and resumes at reduced speed.
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional

import structlog

logger = structlog.get_logger("apexhunter.guardrails.circuit_breaker")


class CircuitBreakerTripped(Exception):
    """Raised when the circuit breaker is in tripped state."""

    pass


class AdaptiveCircuitBreaker:
    """
    Monitors target health and auto-sleeps when the target is stressed.

    The breaker operates in three states:
    - CLOSED: Normal operation, all requests allowed.
    - OPEN: Target is stressed, all requests blocked, agent sleeps.
    - HALF_OPEN: Testing if target recovered, requests at reduced speed.
    """

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

    def __init__(
        self,
        error_threshold_percent: float = 5.0,
        latency_degradation_factor: float = 3.0,
        autosleep_duration: int = 900,
        resume_speed_factor: float = 0.5,
        window_size: int = 100,
    ):
        """
        Args:
            error_threshold_percent: % of 5xx errors to trip the breaker.
            latency_degradation_factor: Multiplier over baseline latency to trip.
            autosleep_duration: Seconds to sleep when tripped.
            resume_speed_factor: Speed factor when resuming (0.5 = half speed).
            window_size: Number of recent requests to consider for metrics.
        """
        self._error_threshold = error_threshold_percent
        self._latency_factor = latency_degradation_factor
        self._sleep_duration = autosleep_duration
        self._resume_factor = resume_speed_factor
        self._window_size = window_size

        self._state = self.CLOSED
        self._request_log: list[dict] = []
        self._baseline_latency: Optional[float] = None
        self._sleep_until: Optional[float] = None
        self._total_trips = 0
        self._speed_factor = 1.0
        self._sleep_logged = False

        # Counters
        self._total_requests = 0
        self._total_5xx = 0
        self._total_4xx = 0

        logger.info(
            "circuit_breaker_initialized",
            error_threshold=error_threshold_percent,
            sleep_duration=autosleep_duration,
        )

    @property
    def state(self) -> str:
        return self._state

    @property
    def speed_factor(self) -> float:
        return self._speed_factor

    @property
    def is_sleeping(self) -> bool:
        if self._sleep_until is None:
            return False
        return time.time() < self._sleep_until

    def record_request(
        self,
        status_code: int,
        response_time_ms: float,
    ) -> None:
        """
        Record the result of an outbound request.

        Args:
            status_code: HTTP status code of the response.
            response_time_ms: Round-trip time in milliseconds.
        """
        self._total_requests += 1

        entry = {
            "timestamp": time.time(),
            "status_code": status_code,
            "response_time_ms": response_time_ms,
        }
        self._request_log.append(entry)

        # Keep only the window
        if len(self._request_log) > self._window_size:
            self._request_log = self._request_log[-self._window_size :]

        # Track error counts
        if 500 <= status_code < 600:
            self._total_5xx += 1
        elif 400 <= status_code < 500:
            self._total_4xx += 1

        # Establish baseline latency from first 10 requests
        if self._baseline_latency is None and len(self._request_log) >= 10:
            self._baseline_latency = (
                sum(r["response_time_ms"] for r in self._request_log[:10]) / 10.0
            )
            logger.info(
                "baseline_latency_established",
                baseline_ms=self._baseline_latency,
            )

        # Check if we need to trip
        self._evaluate()

    def _evaluate(self) -> None:
        """Evaluate current metrics and trip if necessary."""
        if self._state == self.OPEN:
            return

        window = self._request_log
        if len(window) < 10:
            return

        # Calculate error rate
        error_count = sum(1 for r in window if 500 <= r["status_code"] < 600)
        error_rate = (error_count / len(window)) * 100.0

        # Calculate average latency
        avg_latency = sum(r["response_time_ms"] for r in window) / len(window)

        # Check error rate threshold
        if error_rate >= self._error_threshold:
            logger.warning(
                "circuit_breaker_tripped_errors",
                error_rate=error_rate,
                threshold=self._error_threshold,
            )
            self._trip()
            return

        # Check latency degradation
        if (
            self._baseline_latency is not None
            and avg_latency > self._baseline_latency * self._latency_factor
        ):
            logger.warning(
                "circuit_breaker_tripped_latency",
                avg_latency_ms=avg_latency,
                baseline_ms=self._baseline_latency,
                factor=self._latency_factor,
            )
            self._trip()

    def _trip(self) -> None:
        """Trip the circuit breaker and enter auto-sleep."""
        self._state = self.OPEN
        self._sleep_until = time.time() + self._sleep_duration
        self._total_trips += 1
        self._sleep_logged = False
        logger.warning(
            "circuit_breaker_auto_sleep",
            sleep_seconds=self._sleep_duration,
            total_trips=self._total_trips,
        )

    async def wait_if_sleeping(self) -> None:
        """
        Async wait if the circuit breaker is in auto-sleep.
        Called before every outbound request.
        """
        if self._state == self.CLOSED:
            return

        if self._state == self.OPEN:
            if self._sleep_until and time.time() < self._sleep_until:
                remaining = self._sleep_until - time.time()
                # Only log once per sleep period, not per caller
                if not self._sleep_logged:
                    self._sleep_logged = True
                    logger.info(
                        "circuit_breaker_sleeping",
                        remaining_seconds=round(remaining, 1),
                    )
                await asyncio.sleep(remaining)

            # Only the first caller performs the state transition
            if self._state == self.OPEN:
                self._state = self.HALF_OPEN
                self._speed_factor = self._resume_factor
                self._request_log.clear()
                self._sleep_logged = False
                logger.info(
                    "circuit_breaker_half_open",
                    speed_factor=self._speed_factor,
                )

        elif self._state == self.HALF_OPEN:
            # If we have enough good requests, close the breaker
            if len(self._request_log) >= 20:
                error_count = sum(1 for r in self._request_log if 500 <= r["status_code"] < 600)
                error_rate = (error_count / len(self._request_log)) * 100.0

                if error_rate < self._error_threshold:
                    self._state = self.CLOSED
                    self._speed_factor = 1.0
                    logger.info("circuit_breaker_closed", reason="target_recovered")
                else:
                    # Still failing, re-trip
                    self._trip()

    def get_delay(self, base_delay: float) -> float:
        """
        Get the adjusted delay based on current speed factor.

        Args:
            base_delay: The base delay between requests in seconds.

        Returns:
            Adjusted delay (higher when speed is reduced).
        """
        if self._speed_factor <= 0:
            return base_delay
        return base_delay / self._speed_factor

    def get_metrics(self) -> dict:
        """Return current health metrics."""
        window = self._request_log
        error_count = sum(1 for r in window if 500 <= r["status_code"] < 600) if window else 0
        error_rate = (error_count / len(window) * 100.0) if window else 0.0
        avg_latency = (sum(r["response_time_ms"] for r in window) / len(window)) if window else 0.0

        return {
            "state": self._state,
            "speed_factor": self._speed_factor,
            "total_requests": self._total_requests,
            "total_5xx_errors": self._total_5xx,
            "total_4xx_errors": self._total_4xx,
            "error_rate_percent": round(error_rate, 2),
            "avg_response_time_ms": round(avg_latency, 2),
            "is_sleeping": self.is_sleeping,
            "sleep_until": self._sleep_until,
            "total_trips": self._total_trips,
        }
