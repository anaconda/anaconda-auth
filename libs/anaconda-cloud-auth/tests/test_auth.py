from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING
from typing import Any

import pytest

from anaconda_cloud_auth import Client
from anaconda_cloud_auth import login
from anaconda_cloud_auth import logout
from anaconda_cloud_auth import token
from anaconda_cloud_auth.exceptions import TokenNotFoundError
from anaconda_cloud_auth.token import TokenInfo

if TYPE_CHECKING:
    from _pytest.monkeypatch import MonkeyPatch


@pytest.fixture(autouse=True)
def empty_test_keyring(monkeypatch: MonkeyPatch) -> Iterator[None]:
    """Ensure the test keyring is empty at the beginning of each test"""
    monkeypatch.setattr(token, "KEYRING_NAME", "Anaconda Cloud Test")
    with pytest.raises(TokenNotFoundError):
        TokenInfo.load()
    yield
    try:
        TokenInfo().delete()
    except TokenNotFoundError:
        pass


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
def test_login_legacy_iam(is_not_none: Any) -> None:
    login()
    token_info = TokenInfo.load()
    assert token_info == {
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


def test_logout_multiple_okay() -> None:
    """We can logout multiple times and no exception is raised."""
    for _ in range(2):
        logout()
