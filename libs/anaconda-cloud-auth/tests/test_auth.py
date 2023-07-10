from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING
from typing import Any

import pytest
from keyring.backend import KeyringBackend
from pytest_mock import MockerFixture

from anaconda_cloud_auth import Client
from anaconda_cloud_auth import login
from anaconda_cloud_auth import logout
from anaconda_cloud_auth.config import AuthConfig
from anaconda_cloud_auth.token import TokenInfo
from anaconda_cloud_auth.token import TokenNotFoundError

if TYPE_CHECKING:
    from _pytest.monkeypatch import MonkeyPatch


class MockedKeyring(KeyringBackend):
    priority = 10000.0  # type: ignore

    def __init__(self) -> None:
        super().__init__()
        self._data: dict = defaultdict(dict)

    def set_password(self, service: str, username: str, password: str) -> None:
        self._data[service][username] = password

    def get_password(self, service: str, username: str) -> str | None:
        return self._data.get(service, {}).get(username, None)


@pytest.fixture(autouse=True)
def set_keyring_name(mocker: MockerFixture) -> None:
    mocker.patch("anaconda_cloud_auth.token.KEYRING_NAME", "Anaconda Cloud Test")


@pytest.fixture(autouse=True)
def set_environment_variables(monkeypatch: MonkeyPatch) -> None:
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


def test_token_not_found() -> None:
    client = Client()
    with pytest.raises(TokenNotFoundError):
        _ = client.get("/api/account")


def test_logout_multiple_okay() -> None:
    """We can logout multiple times and no exception is raised."""
    auth_config = AuthConfig(domain="test")
    token_info = TokenInfo(api_key="key", domain=auth_config.domain)
    token_info.save()
    assert TokenInfo.load(auth_config.domain).dict()
    for _ in range(2):
        logout(auth_config)
