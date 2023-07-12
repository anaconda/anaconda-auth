from pytest_mock import MockerFixture

from anaconda_cloud_auth.config import AuthConfig


def test_legacy() -> None:
    config = AuthConfig(domain="anaconda.cloud/api/iam")
    assert config.oidc.authorization_endpoint == "https://anaconda.cloud/authorize"
    assert config.oidc.token_endpoint == "https://anaconda.cloud/api/iam/token"


def test_well_known_headers(mocker: MockerFixture) -> None:
    import requests

    spy = mocker.spy(requests, "get")

    config = AuthConfig()
    assert config.oidc
    spy.assert_called_once()
    assert (
        spy.call_args.kwargs.get("headers", {})
        .get("User-Agent")
        .startswith("anaconda-cloud-auth")
    )
