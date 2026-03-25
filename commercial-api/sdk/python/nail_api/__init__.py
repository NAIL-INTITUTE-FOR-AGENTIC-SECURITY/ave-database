"""
NAIL Institute AVE API — Python SDK

Official Python client for the NAIL Institute Agentic Vulnerability
Enumeration (AVE) API.

Usage:
    from nail_api import NailClient

    client = NailClient(api_key="your-api-key")
    cards = client.cards.list(severity="critical")
"""

__version__ = "0.1.0"
__all__ = ["NailClient"]


class NailClient:
    """Main client for the NAIL Institute AVE API.

    Args:
        api_key: Your NAIL API key.
        base_url: API base URL. Defaults to production.
        timeout: Request timeout in seconds.
    """

    DEFAULT_BASE_URL = "https://api.nailinstitute.org/v2"

    def __init__(
        self,
        api_key: str,
        base_url: str | None = None,
        timeout: int = 30,
    ):
        self.api_key = api_key
        self.base_url = base_url or self.DEFAULT_BASE_URL
        self.timeout = timeout

        # Sub-clients (stubs — implemented in full SDK)
        self.cards = _CardsClient(self)
        self.webhooks = _WebhooksClient(self)
        self.export = _ExportClient(self)
        self.risk = _RiskClient(self)
        self.compliance = _ComplianceClient(self)
        self.certification = _CertificationClient(self)
        self.analytics = _AnalyticsClient(self)


class _CardsClient:
    """AVE card operations."""

    def __init__(self, client: NailClient):
        self._client = client

    def list(self, **filters):
        """List cards with optional filters."""
        raise NotImplementedError("Full SDK coming soon")

    def get(self, ave_id: str):
        """Get a specific card by AVE ID."""
        raise NotImplementedError("Full SDK coming soon")

    def search(self, query: str, **filters):
        """Full-text search across cards."""
        raise NotImplementedError("Full SDK coming soon")

    def diff(self, since: str):
        """Get changes since a timestamp."""
        raise NotImplementedError("Full SDK coming soon")


class _WebhooksClient:
    """Webhook management (Pro+)."""

    def __init__(self, client: NailClient):
        self._client = client

    def list(self):
        raise NotImplementedError("Full SDK coming soon")

    def create(self, url: str, events: list[str]):
        raise NotImplementedError("Full SDK coming soon")

    def delete(self, webhook_id: str):
        raise NotImplementedError("Full SDK coming soon")

    def test(self, webhook_id: str):
        raise NotImplementedError("Full SDK coming soon")


class _ExportClient:
    """Bulk export operations (Pro+)."""

    def __init__(self, client: NailClient):
        self._client = client

    def create(self, format: str = "json", filters: dict | None = None):
        raise NotImplementedError("Full SDK coming soon")

    def status(self, job_id: str):
        raise NotImplementedError("Full SDK coming soon")


class _RiskClient:
    """Risk scoring (Enterprise)."""

    def __init__(self, client: NailClient):
        self._client = client

    def score(self, system: dict):
        raise NotImplementedError("Full SDK coming soon")


class _ComplianceClient:
    """Regulatory compliance mapping."""

    def __init__(self, client: NailClient):
        self._client = client

    def map(self, framework: str, categories: list[str] | None = None):
        raise NotImplementedError("Full SDK coming soon")


class _CertificationClient:
    """Certification verification."""

    def __init__(self, client: NailClient):
        self._client = client

    def verify(self, cert_id: str):
        raise NotImplementedError("Full SDK coming soon")


class _AnalyticsClient:
    """Analytics queries (Enterprise)."""

    def __init__(self, client: NailClient):
        self._client = client

    def query(self, metric: str, **kwargs):
        raise NotImplementedError("Full SDK coming soon")
