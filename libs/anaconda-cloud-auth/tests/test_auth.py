from __future__ import annotations

from typing import TYPE_CHECKING
from typing import Any
from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture

from anaconda_cloud_auth import __version__
from anaconda_cloud_auth import login
from anaconda_cloud_auth.actions import _get_api_key
from anaconda_cloud_auth.client import BaseClient
from anaconda_cloud_auth.config import AuthConfig
from anaconda_cloud_auth.token import TokenInfo

if TYPE_CHECKING:
    from _pytest.monkeypatch import MonkeyPatch


@pytest.fixture(autouse=True)
def set_dev_env_vars(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv(
        "ANACONDA_CLOUD_API_DOMAIN", "nucleus-latest.anacondaconnect.com"
    )
    monkeypatch.setenv("ANACONDA_CLOUD_AUTH_DOMAIN", "dev.id.anaconda.cloud")
    monkeypatch.setenv("ANACONDA_CLOUD_AUTH_CLIENT_ID", "cloud-cli-test-4")


@pytest.mark.integration
def test_login_to_token_info(is_not_none: Any) -> None:
    auth_config = AuthConfig()

    login(auth_config=auth_config, basic=False)
    keyring_token = TokenInfo.load(auth_config.domain)

    assert keyring_token == {
        "domain": auth_config.domain,
        "username": None,
        "api_key": is_not_none,
    }


@pytest.mark.xfail(reason="the route currently does not accept an api key")
@pytest.mark.integration
def test_get_auth_info(is_not_none: Any) -> None:
    login()
    client = BaseClient()
    response = client.get("/api/account")
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


class MockResponse:
    def __init__(self, json_data: dict[str, Any], status_code: int):
        self.json_data = json_data
        self.status_code = status_code

    def json(self) -> dict[str, Any]:
        return self.json_data


class MockedRequest:
    def __init__(self) -> None:
        self.called_with_args: tuple[Any] = ()  # type: ignore
        self.called_with_kwargs: dict[str, Any] = {}

    def __call__(self, *args: Any, **kwargs: Any) -> MockResponse:
        self.called_with_args = args  # type: ignore
        self.called_with_kwargs = kwargs
        return MockResponse(status_code=201, json_data={"api_key": "some-jwt"})


@pytest.fixture()
def mocked_request(mocker: MockerFixture) -> MockedRequest:
    """A mocked post request returning an API key."""

    # This could be generalized further, but it may not be worth the effort
    # For now, this mimics a fixed POST request with fixed mocked return data

    mocked_request = MockedRequest()
    mocker.patch("requests.post", mocked_request)
    return mocked_request


def test_get_api_key(mocked_request: MockedRequest) -> None:
    """When we get an API key, we assign appropriate generic scopes and tags."""
    key = _get_api_key("some_access_token")
    assert key == "some-jwt"

    headers = mocked_request.called_with_kwargs["headers"]
    assert headers["Authorization"].startswith("Bearer")

    data = mocked_request.called_with_kwargs["json"]
    assert data == {
        "scopes": ["cloud:read", "cloud:write"],
        "tags": [f"anaconda-cloud-auth/v{__version__}"],
    }
