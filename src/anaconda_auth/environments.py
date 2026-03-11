from typing import Optional

from anaconda_auth._conda.environments_config import configure_conda_for_environments
from anaconda_auth.client import BaseClient


def fetch_org_features() -> Optional[list]:
    """Fetch organization features from userinfo."""
    try:
        client = BaseClient()
        resp = client.get("/api/auth/oauth2/userinfo")
        resp.raise_for_status()
        return resp.json().get("organization_features") or []
    except Exception:
        return None


def get_environments_org(org_features: list) -> Optional[str]:
    """Return the org name of the first org with environments enabled,
    or None if no org has it."""
    for org in org_features:
        if "environments" in org.get("features", []):
            return org.get("org", "")
    return None


def check_and_configure_environments() -> None:
    """Fetch org features, check for environments, configure conda."""
    org_features = fetch_org_features()
    if org_features is None:
        return

    org_name = get_environments_org(org_features)
    if org_name is not None:
        configure_conda_for_environments(org_name)
