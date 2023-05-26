from __future__ import annotations

import time
from collections.abc import Iterator
from typing import TYPE_CHECKING
from typing import Any

import pytest

from anaconda_cloud_auth import Client
from anaconda_cloud_auth import login
from anaconda_cloud_auth import logout
from anaconda_cloud_auth import token
from anaconda_cloud_auth.token import TokenInfo
from anaconda_cloud_auth.token import TokenNotFoundError

if TYPE_CHECKING:
    from _pytest.monkeypatch import MonkeyPatch


@pytest.fixture(autouse=True)
def empty_test_keyring(monkeypatch: MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(token, "KEYRING_NAME", "Anaconda Cloud Test")
    with pytest.raises(TokenNotFoundError):
        TokenInfo.load()
    yield
    try:
        TokenInfo().delete()
    except TokenNotFoundError:
        pass


@pytest.mark.integration
def test_login_legacy_iam(is_not_none: Any) -> None:
    login()
    token_info = TokenInfo.load()
    assert token_info == {
        "access_token": is_not_none,
        "refresh_token": is_not_none,
        "expires_at": is_not_none,
        "username": None,
        "id_token": None,
    }


@pytest.mark.integration
def test_refresh_legacy_iam(is_not_none: Any) -> None:
    token_info = login()
    old_token_dict = TokenInfo.load().dict()

    # We need to wait at least 1 second to ensure the timestamp changes (one-second accuracy)
    time.sleep(1)
    token_info.refresh()

    new_token_dict = TokenInfo.load().dict()
    assert old_token_dict != new_token_dict
    assert old_token_dict["access_token"] != new_token_dict["access_token"]
    assert old_token_dict["refresh_token"] == new_token_dict["refresh_token"]
    assert old_token_dict["expires_at"] < new_token_dict["expires_at"]


@pytest.mark.integration
def test_get_auth_info(is_not_none: Any) -> None:
    login()
    client = Client()
    response = client.get("/api/account")
    assert response.json() == {
        "user": is_not_none,
        "profile": is_not_none,
        "subscriptions": is_not_none,
    }


def test_logout_multiple_okay() -> None:
    """We can logout multiple times and no exception is raised."""
    for _ in range(2):
        logout()
