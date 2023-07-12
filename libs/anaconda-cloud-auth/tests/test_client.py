from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from pytest_mock import MockerFixture

from anaconda_cloud_auth import Client
from anaconda_cloud_auth.exceptions import LoginRequiredError
from anaconda_cloud_auth.token import TokenInfo

if TYPE_CHECKING:
    from _pytest.monkeypatch import MonkeyPatch


def test_login_required_error() -> None:
    client = Client()
    with pytest.raises(LoginRequiredError):
        _ = client.get("/api/account")


def test_anonymous_endpoint(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("ANACONDA_CLOUD_API_DOMAIN", "anaconda.cloud")
    monkeypatch.setenv("ANACONDA_CLOUD_AUTH_DOMAIN", "dummy")

    client = Client()
    response = client.get("/api/catalogs/examples")
    assert "Authorization" not in response.request.headers.keys()
    assert response.status_code == 200


def test_token_included(
    mocker: MockerFixture, monkeypatch: MonkeyPatch, outdated_token_info: TokenInfo
) -> None:
    monkeypatch.setenv("ANACONDA_CLOUD_AUTH_DOMAIN", "mocked-domain")
    mocker.patch("anaconda_cloud_auth.token.TokenInfo.expired", False)

    outdated_token_info.save()

    client = Client()
    response = client.get("/api/catalogs/examples")
    assert (
        response.request.headers.get("Authorization")
        == f"Bearer {outdated_token_info.api_key}"
    )
