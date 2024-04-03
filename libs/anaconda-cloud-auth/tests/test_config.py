import pytest
import requests
import responses
from pytest_mock import MockerFixture

from anaconda_cloud_auth.config import AuthConfig


@pytest.fixture(autouse=True)
def mock_openid_configuration():
    """Mock return value of openid configuration to prevent requiring actual network calls."""
    expected = {
        "authorization_endpoint": "https://anaconda.cloud/authorize",
        "token_endpoint": "https://anaconda.cloud/api/iam/token",
        "jwks_uri": "NOT_NEEDED_FOR_TESTS",
    }
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        # These reflect the two URLs, for which there is a CloudFlare rule to return the same
        # configuration.
        # TODO: Adjust once we are confident we don't need that CloudFlare rule anymore
        rsps.get(
            url="https://id.anaconda.cloud/.well-known/openid-configuration",
            json=expected,
        )
        rsps.get(
            url="https://anaconda.cloud/api/iam/.well-known/openid-configuration",
            json=expected,
        )
        yield rsps


def test_legacy() -> None:
    config = AuthConfig(domain="anaconda.cloud/api/iam")
    assert config.oidc.authorization_endpoint == "https://anaconda.cloud/authorize"
    assert config.oidc.token_endpoint == "https://anaconda.cloud/api/iam/token"


def test_well_known_headers(mocker: MockerFixture) -> None:
    spy = mocker.spy(requests, "get")

    config = AuthConfig()
    assert config.oidc
    spy.assert_called_once()
    assert (
        spy.call_args.kwargs.get("headers", {})
        .get("User-Agent")
        .startswith("anaconda-cloud-auth")
    )
