from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from pytest_mock import MockerFixture

from anaconda_cloud_auth.client import BaseClient
from anaconda_cloud_auth.client import client_factory
from anaconda_cloud_auth.exceptions import LoginRequiredError
from anaconda_cloud_auth.token import TokenInfo

if TYPE_CHECKING:
    from _pytest.monkeypatch import MonkeyPatch


def test_login_required_error() -> None:
    client = BaseClient()
    with pytest.raises(LoginRequiredError):
        _ = client.get("/api/account")


def test_user_agent_client_factory() -> None:
    Client = client_factory("my-app/version")
    client = Client()
    response = client.get("/api/catalogs/examples")
    assert response.request.headers.get("User-Agent") == "my-app/version"


def test_anonymous_endpoint(monkeypatch: MonkeyPatch, disable_dot_env: None) -> None:
    _ = disable_dot_env
    monkeypatch.setenv("ANACONDA_CLOUD_API_DOMAIN", "anaconda.cloud")
    monkeypatch.setenv("ANACONDA_CLOUD_AUTH_DOMAIN", "dummy")
    monkeypatch.delenv("ANACONDA_CLOUD_API_KEY", raising=False)

    client = BaseClient()
    response = client.get("/api/catalogs/examples")
    assert "Authorization" not in response.request.headers.keys()
    assert response.status_code == 200


def test_token_included(
    mocker: MockerFixture,
    monkeypatch: MonkeyPatch,
    outdated_token_info: TokenInfo,
    disable_dot_env: None,
) -> None:
    _ = disable_dot_env
    monkeypatch.setenv("ANACONDA_CLOUD_AUTH_DOMAIN", "mocked-domain")
    mocker.patch("anaconda_cloud_auth.token.TokenInfo.expired", False)
    monkeypatch.delenv("ANACONDA_CLOUD_API_KEY", raising=False)

    outdated_token_info.save()

    client = BaseClient()
    response = client.get("/api/catalogs/examples")
    assert (
        response.request.headers.get("Authorization")
        == f"Bearer {outdated_token_info.api_key}"
    )


def test_api_key_env_variable_over_keyring(
    outdated_token_info: TokenInfo, monkeypatch: MonkeyPatch
) -> None:
    outdated_token_info.save()
    monkeypatch.setenv("ANACONDA_CLOUD_API_KEY", "set-in-env")

    client = BaseClient()
    assert client.config.key == "set-in-env"

    response = client.get("/api/catalogs/examples")
    assert response.request.headers.get("Authorization") == "Bearer set-in-env"


def test_api_key_init_arg_over_variable(
    outdated_token_info: TokenInfo, monkeypatch: MonkeyPatch
) -> None:
    outdated_token_info.save()
    monkeypatch.setenv("ANACONDA_CLOUD_API_KEY", "set-in-env")

    client = BaseClient(api_key="set-in-init")
    assert client.config.key == "set-in-init"

    response = client.get("/api/catalogs/examples")
    assert response.request.headers.get("Authorization") == "Bearer set-in-init"
