from __future__ import annotations

import os
from typing import TYPE_CHECKING
from typing import Any
from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture
from requests.exceptions import SSLError

from anaconda_cloud_auth import __version__
from anaconda_cloud_auth import login
from anaconda_cloud_auth.actions import get_api_key
from anaconda_cloud_auth.client import BaseClient
from anaconda_cloud_auth.config import AuthConfig
from anaconda_cloud_auth.token import TokenInfo

from .conftest import MockedRequest

if TYPE_CHECKING:
    from _pytest.monkeypatch import MonkeyPatch

HERE = os.path.dirname(__file__)


@pytest.fixture(autouse=True)
def set_dev_env_vars(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv(
        "ANACONDA_CLOUD_API_DOMAIN", "nucleus-latest.anacondaconnect.com"
    )
    monkeypatch.setenv("ANACONDA_CLOUD_AUTH_DOMAIN", "dev.id.anaconda.cloud")
    monkeypatch.setenv(
        "ANACONDA_CLOUD_AUTH_CLIENT_ID", "83d245e3-6312-4f44-9298-1f5b32a13769"
    )


@pytest.mark.integration
@pytest.mark.usefixtures("integration_test_client")
def test_login_to_token_info(is_not_none: Any) -> None:
    auth_config = AuthConfig()
    keyring_token = TokenInfo.load(auth_config.domain)

    assert keyring_token == {
        "domain": auth_config.domain,
        "username": None,
        "api_key": is_not_none,
    }


@pytest.mark.integration
@pytest.mark.usefixtures("integration_test_client_setup")
def test_login_ssl_verify_true(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", os.path.join(HERE, "mock-cert.pem"))

    with pytest.raises(SSLError):
        login(ssl_verify=True, force=True, basic=True)


@pytest.mark.integration
@pytest.mark.usefixtures("integration_test_client_setup")
def test_login_ssl_verify_false(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", os.path.join(HERE, "mock-cert.pem"))

    login(ssl_verify=False, force=True, basic=True)


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
    def _mocked_login(auth_config: AuthConfig, basic: bool) -> None:
        TokenInfo(domain=auth_config.domain, api_key="from-login").save()

    mocker.patch("anaconda_cloud_auth.actions._do_login", _mocked_login)
    from anaconda_cloud_auth import actions

    login_spy = mocker.spy(actions, "_do_login")
    return login_spy


def test_login_no_existing_token(mocked_do_login: MagicMock) -> None:
    auth_config = AuthConfig()
    login(auth_config=auth_config)

    assert TokenInfo.load(auth_config.domain).api_key == "from-login"
    mocked_do_login.assert_called_once()


def test_login_has_valid_token(
    mocked_do_login: MagicMock, mocker: MockerFixture
) -> None:
    auth_config = AuthConfig()

    mocker.patch("anaconda_cloud_auth.token.TokenInfo.expired", False)
    TokenInfo(domain=auth_config.domain, api_key="pre-existing").save()

    login(auth_config=auth_config)
    mocked_do_login.assert_not_called()

    assert TokenInfo.load(auth_config.domain).api_key == "pre-existing"


def test_force_login_with_valid_token(
    mocked_do_login: MagicMock, mocker: MockerFixture
) -> None:
    auth_config = AuthConfig()

    mocker.patch("anaconda_cloud_auth.token.TokenInfo.expired", False)
    TokenInfo(domain=auth_config.domain, api_key="pre-existing").save()

    login(auth_config=auth_config, force=True)
    mocked_do_login.assert_called_once()

    assert TokenInfo.load(auth_config.domain).api_key == "from-login"


def test_login_has_expired_token(
    mocked_do_login: MagicMock, mocker: MockerFixture
) -> None:
    auth_config = AuthConfig()

    mocker.patch("anaconda_cloud_auth.token.TokenInfo.expired", True)
    TokenInfo(domain=auth_config.domain, api_key="pre-existing-expired").save()

    login(auth_config=auth_config)
    mocked_do_login.assert_called_once()

    assert TokenInfo.load(auth_config.domain).api_key == "from-login"


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
        "scopes": ["cloud:read", "cloud:write"],
        "tags": [f"anaconda-cloud-auth/v{__version__}"],
    }


@pytest.mark.usefixtures("with_aau_token")
def test_get_api_key_with_aau_token(mocked_request: MockedRequest) -> None:
    """When we get an API key, we assign appropriate generic scopes and tags."""

    key = get_api_key("some_access_token")
    assert key == "some-jwt"

    headers = mocked_request.called_with_kwargs["headers"]
    assert headers["Authorization"].startswith("Bearer")
    assert headers["X-AAU-CLIENT"] == "anon-token"
