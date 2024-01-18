from __future__ import annotations

import warnings
from typing import TYPE_CHECKING
from uuid import uuid4

import pytest
from pytest_mock import MockerFixture

from anaconda_cloud_auth.client import BaseClient
from anaconda_cloud_auth.client import client_factory
from anaconda_cloud_auth.exceptions import LoginRequiredError
from anaconda_cloud_auth.token import TokenInfo

from .conftest import MockedRequest

if TYPE_CHECKING:
    from _pytest.monkeypatch import MonkeyPatch


def test_login_required_error() -> None:
    client = BaseClient()
    client.auth = None

    with pytest.raises(LoginRequiredError):
        _ = client.get("/api/account")


def test_client_factory_user_agent() -> None:
    client = client_factory("my-app/version")
    response = client.get("/api/catalogs/examples")
    assert response.request.headers.get("User-Agent") == "my-app/version"
    assert "Api-Version" not in response.request.headers


def test_client_factory_api_version() -> None:
    client = client_factory(user_agent="my-app/version", api_version="2023.01.01")
    response = client.get("/api/catalogs/examples")
    assert response.request.headers.get("User-Agent") == "my-app/version"
    assert response.request.headers.get("Api-Version") == "2023.01.01"


def test_client_subclass_api_version() -> None:
    class Client(BaseClient):
        _user_agent = "my-app/version"
        _api_version = "2023.01.01"

    client = Client()
    response = client.get("/api/catalogs/examples")
    assert response.request.headers.get("User-Agent") == "my-app/version"
    assert response.request.headers.get("Api-Version") == "2023.01.01"


@pytest.mark.parametrize(
    "attr_name, value, expected_base_uri",
    [
        ("domain", "anaconda.cloud", "https://anaconda.cloud"),
        ("domain", "dev.anaconda.cloud", "https://dev.anaconda.cloud"),
        ("base_uri", "https://anaconda.cloud", "https://anaconda.cloud"),
        ("base_uri", "https://dev.anaconda.cloud", "https://dev.anaconda.cloud"),
    ],
)
def test_client_base_uri(attr_name: str, value: str, expected_base_uri: str) -> None:
    client = BaseClient(**{attr_name: value})
    assert client._base_uri == expected_base_uri


def test_client_base_uri_and_domain_raises_error() -> None:
    with pytest.raises(ValueError):
        BaseClient(domain="anaconda.cloud", base_uri="https://anaconda.cloud")


@pytest.fixture()
def mocked_request(mocker: MockerFixture) -> MockedRequest:
    """A mocked request, returning a custom response."""

    mocked_request = MockedRequest(
        response_status_code=200, response_headers={"Min-Api-Version": "2023.02.02"}
    )
    mocker.patch("requests.Session.request", mocked_request)
    return mocked_request


@pytest.mark.parametrize(
    "api_version, warning_expected", [("2023.01.01", True), ("2023.03.01", False)]
)
def test_client_min_api_version_header(
    mocked_request: MockedRequest, api_version: str, warning_expected: bool
) -> None:
    client = client_factory(user_agent="client/0.1.0", api_version=api_version)
    with warnings.catch_warnings(record=True) as w:
        response = client.get("/api/something")

    assert response.status_code == 200
    assert response.headers.get("Min-Api-Version") == "2023.02.02"

    if warning_expected:
        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)
        assert (
            "Client API version is 2023.01.01, minimum supported API version is 2023.02.02. "
            "You may need to update your client." == str(w[0].message)
        )
    else:
        assert len(w) == 0


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


def test_name_reverts_to_email(mocker: MockerFixture) -> None:
    account = {
        "user": {
            "id": "uuid",
            "email": "me@example.com",
            "first_name": None,
            "last_name": None,
        }
    }

    mocker.patch(
        "anaconda_cloud_auth.client.BaseClient.account",
        return_value=account,
        new_callable=mocker.PropertyMock,
    )
    client = BaseClient()

    assert client.email == "me@example.com"
    assert client.name == client.email


def test_first_and_last_name(mocker: MockerFixture) -> None:
    account = {
        "user": {
            "id": "uuid",
            "email": "me@example.com",
            "first_name": "Anaconda",
            "last_name": "User",
        }
    }

    mocker.patch(
        "anaconda_cloud_auth.client.BaseClient.account",
        return_value=account,
        new_callable=mocker.PropertyMock,
    )
    client = BaseClient()

    assert client.email == "me@example.com"
    assert client.name == "Anaconda User"


def test_gravatar_missing(mocker: MockerFixture) -> None:
    account = {
        "user": {
            "id": "uuid",
            "email": f"{uuid4()}@example.com",
            "first_name": "Anaconda",
            "last_name": "User",
        }
    }

    mocker.patch(
        "anaconda_cloud_auth.client.BaseClient.account",
        return_value=account,
        new_callable=mocker.PropertyMock,
    )
    client = BaseClient()

    assert client.avatar is None


def test_gravatar_found(mocker: MockerFixture) -> None:
    account = {
        "user": {
            "id": "uuid",
            "email": "test1@example.com",
            "first_name": "Anaconda",
            "last_name": "User",
        }
    }

    mocker.patch(
        "anaconda_cloud_auth.client.BaseClient.account",
        return_value=account,
        new_callable=mocker.PropertyMock,
    )
    client = BaseClient()
    assert client.avatar is not None


def test_extra_headers_dict() -> None:
    extra_headers = {"X-Extra": "stuff"}
    client = BaseClient(api_version="ver", extra_headers=extra_headers)

    res = client.get("api/something")
    assert res.request.headers["X-Extra"] == "stuff"
    assert res.request.headers["Api-Version"] == "ver"


def test_extra_headers_string() -> None:
    extra_headers = '{"X-Extra": "stuff"}'
    client = BaseClient(api_version="ver", extra_headers=extra_headers)

    res = client.get("api/something")
    assert res.request.headers["X-Extra"] == "stuff"
    assert res.request.headers["Api-Version"] == "ver"


def test_extra_headers_non_overwrite() -> None:
    extra_headers = {"X-Extra": "stuff", "Api-Version": "never overwrite"}
    client = BaseClient(api_version="ver", extra_headers=extra_headers)

    res = client.get("api/something")
    assert res.request.headers["X-Extra"] == "stuff"
    assert res.request.headers["Api-Version"] == "ver"


def test_extra_headers_bad_json() -> None:
    extra_headers = "nope"

    with pytest.raises(ValueError):
        _ = BaseClient(api_version="ver", extra_headers=extra_headers)


def test_extra_headers_env_var(monkeypatch: MonkeyPatch) -> None:
    extra_headers = '{"X-Extra": "from-env"}'
    monkeypatch.setenv("ANACONDA_CLOUD_API_EXTRA_HEADERS", extra_headers)

    client = BaseClient(api_key="set-in-init")

    res = client.get("api/something")
    assert res.request.headers["X-Extra"] == "from-env"
