from __future__ import annotations

import os
from typing import Any
from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture

from anaconda_auth import __version__
from anaconda_auth import login
from anaconda_auth.actions import get_api_key
from anaconda_auth.actions import is_logged_in
from anaconda_auth.client import BaseClient
from anaconda_auth.config import AnacondaAuthConfig
from anaconda_auth.token import TOKEN_INFO_VERSION
from anaconda_auth.token import TokenInfo

from .conftest import MockedRequest

HERE = os.path.dirname(__file__)


def test_login_to_api_key(mocker: MockerFixture) -> None:
    mocker.patch("anaconda_auth.actions.get_api_key", return_value="api-key")
    mocker.patch("anaconda_auth.actions._do_auth_flow")

    login()

    config = AnacondaAuthConfig()
    keyring_token = TokenInfo.load(config.domain)

    assert keyring_token.model_dump() == {
        "domain": config.domain,
        "username": None,
        "repo_tokens": [],
        "api_key": "api-key",
        "version": TOKEN_INFO_VERSION,
    }


def test_login_ssl_verify(mocker: MockerFixture, api_key: str) -> None:
    mocker.patch("anaconda_auth.actions.get_api_key", return_value=api_key)
    do_auth_flow = mocker.patch("anaconda_auth.actions._do_auth_flow")

    login(ssl_verify=True)
    assert do_auth_flow.call_args_list[-1].kwargs["config"].ssl_verify


def test_login_no_ssl_verify(mocker: MockerFixture, api_key: str) -> None:
    mocker.patch("anaconda_auth.actions.get_api_key", return_value=api_key)
    do_auth_flow = mocker.patch("anaconda_auth.actions._do_auth_flow")

    login(ssl_verify=False)
    assert not do_auth_flow.call_args_list[-1].kwargs["config"].ssl_verify


@pytest.mark.integration
def test_get_auth_info(integration_test_client: BaseClient, is_not_none: Any) -> None:
    response = integration_test_client.get("/api/account")
    assert response.status_code == 200
    assert response.json() == {
        "user": is_not_none,
        "profile": is_not_none,
        "subscriptions": is_not_none,
    }


@pytest.fixture
def mocked_do_login(mocker: MockerFixture) -> MagicMock:
    def _mocked_login(config: AnacondaAuthConfig, basic: bool) -> None:
        TokenInfo(domain=config.domain, api_key="from-login").save()

    mocker.patch("anaconda_auth.actions._do_login", _mocked_login)
    from anaconda_auth import actions

    login_spy = mocker.spy(actions, "_do_login")
    return login_spy


def test_login_no_existing_token(mocked_do_login: MagicMock) -> None:
    config = AnacondaAuthConfig()
    login(config=config)

    assert TokenInfo.load(config.domain).api_key == "from-login"
    mocked_do_login.assert_called_once()


def test_login_has_valid_token(
    mocked_do_login: MagicMock, mocker: MockerFixture
) -> None:
    config = AnacondaAuthConfig()

    mocker.patch("anaconda_auth.token.TokenInfo.expired", False)
    TokenInfo(domain=config.domain, api_key="pre-existing").save()

    login(config=config)
    mocked_do_login.assert_not_called()

    assert TokenInfo.load(config.domain).api_key == "pre-existing"


def test_force_login_with_valid_token(
    mocked_do_login: MagicMock, mocker: MockerFixture
) -> None:
    config = AnacondaAuthConfig()

    mocker.patch("anaconda_auth.token.TokenInfo.expired", False)
    TokenInfo(domain=config.domain, api_key="pre-existing").save()

    login(config=config, force=True)
    mocked_do_login.assert_called_once()

    assert TokenInfo.load(config.domain).api_key == "from-login"


def test_login_has_expired_token(
    mocked_do_login: MagicMock, mocker: MockerFixture
) -> None:
    config = AnacondaAuthConfig()

    mocker.patch("anaconda_auth.token.TokenInfo.expired", True)
    TokenInfo(domain=config.domain, api_key="pre-existing-expired").save()

    login(config=config)
    mocked_do_login.assert_called_once()

    assert TokenInfo.load(config.domain).api_key == "from-login"


@pytest.fixture()
def mocked_request(mocker: MockerFixture) -> MockedRequest:
    """A mocked post request returning an API key."""

    # This could be generalized further, but it may not be worth the effort
    # For now, this mimics a fixed POST request with fixed mocked return data

    mocked_request = MockedRequest(
        response_status_code=201, response_data={"api_key": "some-jwt"}
    )
    mocker.patch("requests.post", mocked_request)
    return mocked_request


@pytest.mark.usefixtures("without_aau_token")
def test_get_api_key(mocked_request: MockedRequest) -> None:
    """When we get an API key, we assign appropriate generic scopes and tags."""

    key = get_api_key("some_access_token")
    assert key == "some-jwt"

    headers = mocked_request.called_with_kwargs["headers"]
    assert headers["Authorization"].startswith("Bearer")
    assert "X-AAU-CLIENT" not in headers

    data = mocked_request.called_with_kwargs["json"]
    assert data == {
        "scopes": ["cloud:read", "cloud:write", "repo:read"],
        "tags": [f"anaconda-auth/v{__version__}"],
    }


@pytest.mark.usefixtures("with_aau_token")
def test_get_api_key_with_aau_token(mocked_request: MockedRequest) -> None:
    """When we get an API key, we assign appropriate generic scopes and tags."""

    key = get_api_key("some_access_token")
    assert key == "some-jwt"

    headers = mocked_request.called_with_kwargs["headers"]
    assert headers["Authorization"].startswith("Bearer")
    assert headers["X-AAU-CLIENT"] == "anon-token"


@pytest.mark.usefixtures("save_api_key_to_token")
def test_is_logged_in() -> None:
    assert is_logged_in()
