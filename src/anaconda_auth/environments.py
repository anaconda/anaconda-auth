import logging
from typing import Optional

from anaconda_auth.client import BaseClient

logger = logging.getLogger(__name__)


def fetch_org_features() -> Optional[list]:
    """Fetch organization features from userinfo."""
    try:
        client = BaseClient()
        resp = client.get("/api/auth/oauth2/userinfo")
        resp.raise_for_status()
        return resp.json().get("organization_features") or []
    except Exception:
        return None


def get_environments_orgs(org_features: list) -> list[str]:
    """Return org names that have the environments feature enabled."""
    return [
        org.get("org", "")
        for org in org_features
        if "environments" in org.get("features", [])
    ]