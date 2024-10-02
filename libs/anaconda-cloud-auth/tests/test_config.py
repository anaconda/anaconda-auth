import pytest
import requests
import responses
from pytest_mock import MockerFixture

from anaconda_cloud_auth.config import AnacondaCloudConfig


@pytest.fixture(autouse=True)
def mock_openid_configuration():
    config = AnacondaCloudConfig()
    """Mock return value of openid configuration to prevent requiring actual network calls."""
    expected = {
        "authorization_endpoint": f"https://{config.domain}/authorize",
        "token_endpoint": f"https://{config.domain}/api/iam/token",
        "jwks_uri": "NOT_NEEDED_FOR_TESTS",
    }
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.get(
            url=f"https://{config.domain}/api/iam/.well-known/openid-configuration",
            json=expected,
        )
        yield rsps


def test_legacy() -> None:
    config = AnacondaCloudConfig()
    assert config.oidc.authorization_endpoint == f"https://{config.domain}/authorize"
    assert config.oidc.token_endpoint == f"https://{config.domain}/api/iam/token"


def test_well_known_headers(mocker: MockerFixture) -> None:
    spy = mocker.spy(requests, "get")

    config = AnacondaCloudConfig()
    assert config.oidc
    spy.assert_called_once()
    assert (
        spy.call_args.kwargs.get("headers", {})
        .get("User-Agent")
        .startswith("anaconda-cloud-auth")
    )
