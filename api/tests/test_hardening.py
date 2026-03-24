"""Tests for Phase 2.6 Technical Hardening — rate limiting, security headers,
input validation, metrics, and structured logging."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.server import (
    MetricsCollector,
    SlidingWindowRateLimiter,
    _sanitise_ave_id,
    _sanitise_path_segment,
    _sanitise_query,
    create_app,
)


# ═══════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════

@pytest.fixture()
def client() -> TestClient:
    app = create_app()
    return TestClient(app)


# ═══════════════════════════════════════════════════════════════════════════
# Security Headers
# ═══════════════════════════════════════════════════════════════════════════

class TestSecurityHeaders:
    """Every response must carry hardened security headers."""

    def test_request_id_present(self, client: TestClient) -> None:
        r = client.get("/health")
        assert r.status_code == 200
        assert "X-Request-ID" in r.headers

    def test_hsts_header(self, client: TestClient) -> None:
        r = client.get("/health")
        assert "Strict-Transport-Security" in r.headers
        assert "max-age=" in r.headers["Strict-Transport-Security"]

    def test_nosniff_header(self, client: TestClient) -> None:
        r = client.get("/health")
        assert r.headers.get("X-Content-Type-Options") == "nosniff"

    def test_frame_deny(self, client: TestClient) -> None:
        r = client.get("/health")
        assert r.headers.get("X-Frame-Options") == "DENY"

    def test_csp_header(self, client: TestClient) -> None:
        r = client.get("/health")
        assert "Content-Security-Policy" in r.headers

    def test_referrer_policy(self, client: TestClient) -> None:
        r = client.get("/health")
        assert "Referrer-Policy" in r.headers

    def test_permissions_policy(self, client: TestClient) -> None:
        r = client.get("/health")
        assert "Permissions-Policy" in r.headers

    def test_response_time_header(self, client: TestClient) -> None:
        r = client.get("/health")
        assert "X-Response-Time" in r.headers
        assert r.headers["X-Response-Time"].endswith("ms")

    def test_rate_limit_headers(self, client: TestClient) -> None:
        r = client.get("/health")
        assert "X-RateLimit-Limit" in r.headers
        assert "X-RateLimit-Remaining" in r.headers
        assert "X-RateLimit-Reset" in r.headers

    def test_custom_request_id_forwarded(self, client: TestClient) -> None:
        r = client.get("/health", headers={"X-Request-ID": "test-abc-123"})
        assert r.headers.get("X-Request-ID") == "test-abc-123"


# ═══════════════════════════════════════════════════════════════════════════
# Rate Limiter Unit Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestRateLimiter:
    """Sliding-window rate limiter."""

    def test_allows_under_limit(self) -> None:
        rl = SlidingWindowRateLimiter(max_requests=5, window_seconds=60)
        for _ in range(5):
            allowed, _ = rl.is_allowed("1.2.3.4")
            assert allowed

    def test_blocks_over_limit(self) -> None:
        rl = SlidingWindowRateLimiter(max_requests=3, window_seconds=60)
        for _ in range(3):
            rl.is_allowed("1.2.3.4")
        allowed, headers = rl.is_allowed("1.2.3.4")
        assert not allowed
        assert headers["X-RateLimit-Remaining"] == "0"

    def test_different_ips_independent(self) -> None:
        rl = SlidingWindowRateLimiter(max_requests=2, window_seconds=60)
        for _ in range(2):
            rl.is_allowed("1.1.1.1")
        # 1.1.1.1 is exhausted, but 2.2.2.2 should be fine
        allowed, _ = rl.is_allowed("2.2.2.2")
        assert allowed

    def test_headers_always_present(self) -> None:
        rl = SlidingWindowRateLimiter(max_requests=10, window_seconds=60)
        _, headers = rl.is_allowed("5.5.5.5")
        assert "X-RateLimit-Limit" in headers
        assert "X-RateLimit-Remaining" in headers
        assert "X-RateLimit-Reset" in headers

    def test_cleanup_removes_stale(self) -> None:
        rl = SlidingWindowRateLimiter(max_requests=5, window_seconds=1)
        rl.is_allowed("old-ip")
        # Fake staleness by clearing the deque
        rl._hits["old-ip"].clear()
        rl.cleanup()
        assert "old-ip" not in rl._hits


# ═══════════════════════════════════════════════════════════════════════════
# Metrics Collector Unit Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestMetricsCollector:
    """In-memory metrics tracking."""

    def test_initial_state(self) -> None:
        m = MetricsCollector()
        snap = m.snapshot()
        assert snap["total_requests"] == 0

    def test_record_increments(self) -> None:
        m = MetricsCollector()
        m.record("/health", 200, 1.5)
        m.record("/ave", 200, 2.0)
        m.record("/ave/search", 400, 0.5)
        snap = m.snapshot()
        assert snap["total_requests"] == 3
        assert snap["status_codes"][200] == 2
        assert snap["status_codes"][400] == 1

    def test_rate_limit_tracking(self) -> None:
        m = MetricsCollector()
        m.record_rate_limit()
        m.record_rate_limit()
        snap = m.snapshot()
        assert snap["rate_limited_count"] == 2
        assert snap["status_codes"][429] == 2

    def test_latency_percentiles(self) -> None:
        m = MetricsCollector()
        for i in range(100):
            m.record("/test", 200, float(i))
        snap = m.snapshot()
        assert snap["latency_ms"]["p50"] >= 40
        assert snap["latency_ms"]["p99"] >= 90


# ═══════════════════════════════════════════════════════════════════════════
# Input Validation
# ═══════════════════════════════════════════════════════════════════════════

class TestInputValidation:
    """Input sanitisation helpers."""

    def test_valid_ave_id(self) -> None:
        assert _sanitise_ave_id("AVE-2025-0001") == "AVE-2025-0001"
        assert _sanitise_ave_id("ave-2025-0042") == "AVE-2025-0042"

    def test_invalid_ave_id_raises(self) -> None:
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            _sanitise_ave_id("../../etc/passwd")
        assert exc_info.value.status_code == 400

    def test_invalid_ave_id_sql(self) -> None:
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            _sanitise_ave_id("AVE'; DROP TABLE--")

    def test_query_sanitisation(self) -> None:
        assert _sanitise_query("prompt injection") == "prompt injection"
        # Strips angle brackets, quotes, etc.
        result = _sanitise_query("<script>alert('xss')</script>")
        assert "<" not in result
        assert ">" not in result

    def test_path_segment_traversal(self) -> None:
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            _sanitise_path_segment("")
        clean = _sanitise_path_segment("../../../etc/passwd")
        assert ".." not in clean
        assert "/" not in clean

    def test_severity_validation(self, client: TestClient) -> None:
        r = client.get("/ave/severity/critical")
        assert r.status_code == 200
        r = client.get("/ave/severity/apocalyptic")
        assert r.status_code == 400

    def test_sort_validation(self, client: TestClient) -> None:
        r = client.get("/ave?sort=ave_id")
        assert r.status_code == 200
        r = client.get("/ave?sort=; DROP TABLE")
        assert r.status_code == 400


# ═══════════════════════════════════════════════════════════════════════════
# Metrics Endpoint
# ═══════════════════════════════════════════════════════════════════════════

class TestMetricsEndpoint:
    """GET /metrics returns live stats."""

    def test_metrics_200(self, client: TestClient) -> None:
        r = client.get("/metrics")
        assert r.status_code == 200
        data = r.json()
        assert "total_requests" in data
        assert "latency_ms" in data
        assert "rate_limit_rpm" in data
        assert "cards_loaded" in data

    def test_metrics_increment_after_traffic(self, client: TestClient) -> None:
        # Hit a couple of endpoints first
        client.get("/health")
        client.get("/ave/stats")
        r = client.get("/metrics")
        data = r.json()
        # At least 2 requests counted before /metrics itself
        # (health + stats; /metrics may or may not count itself)
        assert data["total_requests"] >= 2


# ═══════════════════════════════════════════════════════════════════════════
# Health + Version
# ═══════════════════════════════════════════════════════════════════════════

class TestHealthEndpoint:
    """Health check includes version."""

    def test_health_includes_version(self, client: TestClient) -> None:
        r = client.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["version"] == "2.1.0"
        assert data["status"] == "healthy"

    def test_root_includes_metrics_link(self, client: TestClient) -> None:
        r = client.get("/")
        data = r.json()
        assert data["links"]["metrics"] == "/metrics"
        assert data["version"] == "2.1.0"
