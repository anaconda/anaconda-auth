import pytest
import requests
import responses
from pytest import MonkeyPatch
from pytest_mock import MockerFixture

from anaconda_auth.config import AnacondaAuthConfig


@pytest.fixture(autouse=True)
def mock_openid_configuration():
    config = AnacondaAuthConfig()
    """Mock return value of openid configuration to prevent requiring actual network calls."""
    expected = {
        "authorization_endpoint": f"https://auth.{config.domain}/api/auth/oauth2/authorize",
        "token_endpoint": f"https://auth.{config.domain}/api/auth/oauth2/token",
    }
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.get(
            url=f"https://{config.domain}/api/auth/oauth2/.well-known/openid-configuration",
            json=expected,
        )
        yield rsps


def test_well_known_headers(mocker: MockerFixture) -> None:
    spy = mocker.spy(requests, "get")

    config = AnacondaAuthConfig()
    assert config.oidc
    spy.assert_called_once()
    assert (
        spy.call_args.kwargs.get("headers", {})
        .get("User-Agent")
        .startswith("anaconda-auth")
    )


@pytest.mark.parametrize("prefix", ["ANACONDA_AUTH", "ANACONDA_CLOUD"])
def test_env_variables_multiple_names(monkeypatch: MonkeyPatch, prefix: str) -> None:
    monkeypatch.setenv(f"{prefix}_DOMAIN", "mocked-domain")
    config = AnacondaAuthConfig()
    assert config.domain == "mocked-domain"


def test_env_variable_over_default(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("ANACONDA_AUTH_DOMAIN", "set-in-env")
    config = AnacondaAuthConfig()
    assert config.domain == "set-in-env"


def test_init_arg_over_env_variable(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("ANACONDA_AUTH_DOMAIN", "set-in-env")
    config = AnacondaAuthConfig(domain="set-in-init")
    assert config.domain == "set-in-init"
