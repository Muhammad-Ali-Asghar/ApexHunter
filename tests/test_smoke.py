"""
ApexHunter Smoke Tests

These tests verify core components work correctly without requiring
Docker, external services, or installed security tools.
Run with: pytest tests/ -v
"""

import asyncio
import os
import tempfile
import time

import pytest

# ── State Tests ──────────────────────────────────────────────────────

from src.state import (
    ApexState,
    Endpoint,
    AuthToken,
    TaskItem,
    Vulnerability,
    WAFProfile,
    HealthMetrics,
    create_initial_state,
)


class TestState:
    """Tests for the LangGraph state definitions."""

    def test_create_initial_state(self):
        state = create_initial_state(
            target_url="https://example.com",
            target_scope=r"^https?://(.*\.)?example\.com",
            credentials=[{"role": "admin", "username": "admin", "password": "pass"}],
            scan_id="test-001",
        )
        assert state["target_url"] == "https://example.com"
        assert state["scan_id"] == "test-001"
        assert state["current_phase"] == "initialization"
        assert state["auth_credentials"] == [
            {"role": "admin", "username": "admin", "password": "pass"}
        ]
        assert state["vulnerability_report"] == []
        assert state["pivot_count"] == 0
        assert state["max_pivots"] == 3

    def test_initial_state_has_all_keys(self):
        state = create_initial_state(
            target_url="https://example.com",
            target_scope=r".*",
            credentials=[],
            scan_id="test-002",
        )
        expected_keys = [
            "target_url",
            "target_scope",
            "auth_matrix",
            "auth_credentials",
            "discovered_endpoints",
            "openapi_schemas",
            "historical_osint_data",
            "hidden_surface_map",
            "technology_fingerprint",
            "dom_sink_logs",
            "waf_profile",
            "reduced_attack_surface",
            "task_tree",
            "rag_context",
            "completed_tasks",
            "proxy_logs",
            "state_changing_requests",
            "oob_listener_url",
            "oob_interaction_id",
            "oob_findings",
            "vulnerability_report",
            "health_metrics",
            "installed_tools",
            "pivot_count",
            "max_pivots",
            "pivot_vulns",
            "scan_id",
            "scan_start_time",
            "current_phase",
            "errors",
            # Page-by-page architecture fields
            "site_tree",
            "page_captures",
            "page_analyses",
            "current_page_index",
            "pages_completed",
            "pages_requiring_deep_scan",
            "deep_scan_active",
        ]
        for key in expected_keys:
            assert key in state, f"Missing key: {key}"

    def test_endpoint_typed_dict(self):
        ep = Endpoint(
            url="https://example.com/api/users",
            method="GET",
            params=[{"name": "id", "type": "query"}],
            headers={},
            content_type="application/json",
            requires_auth=True,
            source="crawl",
        )
        assert ep["url"] == "https://example.com/api/users"
        assert ep["requires_auth"] is True

    def test_vulnerability_typed_dict(self):
        vuln = Vulnerability(
            vuln_id="VULN-001",
            title="SQL Injection in login",
            vuln_type="sqli",
            owasp_category="A03:2021",
            severity="critical",
            cvss_score=9.8,
            affected_endpoint="/login",
            affected_method="POST",
            affected_param="username",
            evidence="' OR 1=1-- caused auth bypass",
            request_sent="POST /login",
            response_received="200 OK",
            remediation="Use parameterized queries",
            discovered_at=time.time(),
            validated=True,
            is_second_order=False,
            chain_parent=None,
        )
        assert vuln["severity"] == "critical"
        assert vuln["cvss_score"] == 9.8


# ── RoE Gatekeeper Tests ────────────────────────────────────────────

from src.guardrails.roe_gatekeeper import RoEGatekeeper, RoEViolation


class TestRoEGatekeeper:
    """Tests for the Rules of Engagement egress firewall."""

    def setup_method(self):
        self.gk = RoEGatekeeper(r"^https?://(.*\.)?example\.com")

    def test_allows_in_scope_url(self):
        assert self.gk.validate_url("https://example.com/api/test") is True

    def test_allows_subdomain(self):
        assert self.gk.validate_url("https://api.example.com/v1") is True

    def test_blocks_out_of_scope(self):
        with pytest.raises(RoEViolation):
            self.gk.validate_url("https://evil.com/steal")

    def test_blocks_localhost(self):
        with pytest.raises(RoEViolation):
            self.gk.validate_url("http://localhost:8080/admin")

    def test_blocks_aws_metadata(self):
        with pytest.raises(RoEViolation):
            self.gk.validate_url("http://169.254.169.254/latest/meta-data/")

    def test_blocks_google_metadata(self):
        with pytest.raises(RoEViolation):
            self.gk.validate_url("http://metadata.google.internal/v1/")

    def test_blocks_loopback(self):
        with pytest.raises(RoEViolation):
            self.gk.validate_url("http://127.0.0.1:3000/debug")

    def test_validate_or_skip_returns_false(self):
        assert self.gk.validate_or_skip("https://evil.com") is False

    def test_validate_or_skip_returns_true(self):
        assert self.gk.validate_or_skip("https://example.com/ok") is True

    def test_stats_tracking(self):
        self.gk.validate_url("https://example.com/1")
        self.gk.validate_url("https://example.com/2")
        self.gk.validate_or_skip("https://evil.com")
        stats = self.gk.get_stats()
        assert stats["allowed_requests"] == 2
        assert stats["blocked_requests"] == 1


# ── Circuit Breaker Tests ───────────────────────────────────────────

from src.guardrails.circuit_breaker import AdaptiveCircuitBreaker


class TestCircuitBreaker:
    """Tests for the adaptive circuit breaker."""

    def test_starts_closed(self):
        cb = AdaptiveCircuitBreaker()
        assert cb.state == "closed"
        assert cb.speed_factor == 1.0
        assert cb.is_sleeping is False

    def test_normal_requests_stay_closed(self):
        cb = AdaptiveCircuitBreaker(window_size=20)
        for _ in range(20):
            cb.record_request(200, 50.0)
        assert cb.state == "closed"

    def test_trips_on_5xx_spike(self):
        cb = AdaptiveCircuitBreaker(
            error_threshold_percent=5.0,
            window_size=20,
            autosleep_duration=1,
        )
        # Send 10 good requests first (to pass minimum window)
        for _ in range(10):
            cb.record_request(200, 50.0)
        # Then spike with 5xx errors (>5% threshold)
        for _ in range(10):
            cb.record_request(503, 100.0)
        assert cb.state == "open"

    def test_trips_on_latency_degradation(self):
        cb = AdaptiveCircuitBreaker(
            latency_degradation_factor=3.0,
            window_size=20,
            autosleep_duration=1,
        )
        # Establish baseline (10 requests at 50ms)
        for _ in range(10):
            cb.record_request(200, 50.0)
        assert cb._baseline_latency is not None
        # Degrade latency (>3x baseline = >150ms)
        for _ in range(10):
            cb.record_request(200, 500.0)
        assert cb.state == "open"

    def test_get_delay_adjusts_for_speed_factor(self):
        cb = AdaptiveCircuitBreaker()
        assert cb.get_delay(1.0) == 1.0
        cb._speed_factor = 0.5
        assert cb.get_delay(1.0) == 2.0

    def test_metrics_output(self):
        cb = AdaptiveCircuitBreaker()
        for i in range(5):
            cb.record_request(200, 50.0)
        cb.record_request(500, 100.0)
        metrics = cb.get_metrics()
        assert metrics["total_requests"] == 6
        assert metrics["total_5xx_errors"] == 1
        assert metrics["state"] == "closed"

    @pytest.mark.asyncio
    async def test_wait_if_sleeping_noop_when_closed(self):
        cb = AdaptiveCircuitBreaker()
        await cb.wait_if_sleeping()  # Should return immediately
        assert cb.state == "closed"


# ── Flight Recorder Tests ───────────────────────────────────────────

from src.guardrails.flight_recorder import FlightDataRecorder


class TestFlightRecorder:
    """Tests for the WARC audit log."""

    def test_creates_warc_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = FlightDataRecorder(tmpdir, "test-scan")
            warc_path = os.path.join(tmpdir, "apex_test-scan.warc")
            assert os.path.exists(warc_path)

    def test_record_request_returns_id(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = FlightDataRecorder(tmpdir, "test-scan")
            record_id = recorder.record_request(
                method="GET",
                url="https://example.com/api",
                headers={"User-Agent": "ApexHunter"},
                body=None,
                auth_role="admin",
            )
            assert "req:1" in record_id

    def test_hash_chain_integrity(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = FlightDataRecorder(tmpdir, "test-scan")
            genesis_hash = recorder._last_hash
            assert genesis_hash == "0" * 64

            recorder.record_request(
                method="GET",
                url="https://example.com/1",
                headers={},
            )
            hash_after_first = recorder._last_hash
            assert hash_after_first != genesis_hash

            recorder.record_request(
                method="POST",
                url="https://example.com/2",
                headers={},
                body='{"key": "val"}',
            )
            hash_after_second = recorder._last_hash
            assert hash_after_second != hash_after_first

    def test_record_response(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = FlightDataRecorder(tmpdir, "test-scan")
            req_id = recorder.record_request(
                method="GET",
                url="https://example.com",
                headers={},
            )
            recorder.record_response(
                record_id=req_id,
                url="https://example.com",
                status_code=200,
                headers={"Content-Type": "text/html"},
                body="<html>OK</html>",
                response_time_ms=42.5,
            )
            stats = recorder.get_stats()
            assert stats["total_records"] == 1
            assert stats["warc_size_bytes"] > 0

    def test_hashchain_file_created(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = FlightDataRecorder(tmpdir, "test-scan")
            recorder.record_request(method="GET", url="https://example.com", headers={})
            hashchain_path = os.path.join(tmpdir, "apex_test-scan.hashchain")
            assert os.path.exists(hashchain_path)
            with open(hashchain_path) as f:
                lines = f.readlines()
            assert len(lines) == 1
            assert "|request|" in lines[0]

    def test_verify_integrity(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            recorder = FlightDataRecorder(tmpdir, "test-scan")
            recorder.record_request(method="GET", url="https://example.com", headers={})
            assert recorder.verify_integrity() is True


# ── Auth Agent JWT Helpers Tests ─────────────────────────────────────

from src.agents.auth import AuthAgent


class TestAuthHelpers:
    """Tests for auth agent utility methods (no network required)."""

    def setup_method(self):
        self.agent = AuthAgent(http_client=None, config=None)

    def test_looks_like_jwt_valid(self):
        # A real-ish JWT structure (header.payload.signature)
        import base64, json

        header = (
            base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
            .rstrip(b"=")
            .decode()
        )
        payload = (
            base64.urlsafe_b64encode(json.dumps({"sub": "1234567890"}).encode())
            .rstrip(b"=")
            .decode()
        )
        sig = "dummysignature"
        token = f"{header}.{payload}.{sig}"
        assert self.agent._looks_like_jwt(token) is True

    def test_looks_like_jwt_invalid(self):
        assert self.agent._looks_like_jwt("not-a-jwt") is False
        assert self.agent._looks_like_jwt("only.two") is False
        assert self.agent._looks_like_jwt("") is False

    def test_crack_jwt_secret_no_match(self):
        # A JWT with a secret NOT in the dictionary
        import base64, json, hmac, hashlib

        header = (
            base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
        )
        payload = (
            base64.urlsafe_b64encode(json.dumps({"sub": "test"}).encode()).rstrip(b"=").decode()
        )
        signing_input = f"{header}.{payload}".encode()
        sig = (
            base64.urlsafe_b64encode(
                hmac.new(
                    b"this_is_a_very_unique_uncrackable_secret_xyz_123_!@#",
                    signing_input,
                    hashlib.sha256,
                ).digest()
            )
            .rstrip(b"=")
            .decode()
        )
        token = f"{header}.{payload}.{sig}"
        result = self.agent._crack_jwt_secret(token, "HS256")
        assert result is None

    def test_crack_jwt_secret_weak_secret(self):
        # A JWT signed with "secret" (in the dictionary)
        import base64, json, hmac, hashlib

        header = (
            base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
        )
        payload = (
            base64.urlsafe_b64encode(json.dumps({"sub": "test"}).encode()).rstrip(b"=").decode()
        )
        signing_input = f"{header}.{payload}".encode()
        sig = (
            base64.urlsafe_b64encode(hmac.new(b"secret", signing_input, hashlib.sha256).digest())
            .rstrip(b"=")
            .decode()
        )
        token = f"{header}.{payload}.{sig}"
        result = self.agent._crack_jwt_secret(token, "HS256")
        assert result == "secret"
