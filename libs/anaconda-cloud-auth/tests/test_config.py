from anaconda_cloud_auth.config import AuthConfig


def test_legacy() -> None:
    config = AuthConfig(domain="anaconda.cloud/api/iam")
    assert config.oidc.authorization_endpoint == "https://anaconda.cloud/authorize"
    assert config.oidc.token_endpoint == "https://anaconda.cloud/api/iam/token"
