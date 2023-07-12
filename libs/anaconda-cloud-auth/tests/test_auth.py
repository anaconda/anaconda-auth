from __future__ import annotations

from typing import TYPE_CHECKING
from typing import Any

import pytest

from anaconda_cloud_auth import Client
from anaconda_cloud_auth import login
from anaconda_cloud_auth.config import AuthConfig
from anaconda_cloud_auth.token import TokenInfo

if TYPE_CHECKING:
    from _pytest.monkeypatch import MonkeyPatch


@pytest.fixture(autouse=False)
def set_dev_env_vars(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv(
        "ANACONDA_CLOUD_API_DOMAIN", "nucleus-latest.anacondaconnect.com"
    )
    monkeypatch.setenv(
        "ANACONDA_CLOUD_AUTH_DOMAIN", "nucleus-latest.anacondaconnect.com/api/iam"
    )
    monkeypatch.setenv("ANACONDA_CLOUD_AUTH_CLIENT_ID", "cloud-cli-test-4")


@pytest.mark.integration
def test_login_to_token_info(is_not_none: Any) -> None:
    auth_config = AuthConfig()

    token_info = login(auth_config=auth_config, simple=False)
    keyring_token = TokenInfo.load(auth_config.domain)

    assert token_info == keyring_token

    assert token_info == {
        "domain": auth_config.domain,
        "username": None,
        "api_key": is_not_none,
    }


@pytest.mark.integration
def test_get_auth_info(is_not_none: Any) -> None:
    login()
    client = Client()
    response = client.get("/api/account")
    assert response.status_code == 200
    assert response.json() == {
        "user": is_not_none,
        "profile": is_not_none,
        "subscriptions": is_not_none,
    }
