from pathlib import Path
from textwrap import dedent

import pytest
import requests
from pytest import MonkeyPatch
from pytest_mock import MockerFixture
from requests_mock import Mocker as RequestMocker

from anaconda_auth.config import AnacondaAuthConfig
from anaconda_auth.config import AnacondaAuthSite
from anaconda_auth.config import AnacondaAuthSitesConfig
from anaconda_auth.config import AnacondaCloudConfig
from anaconda_auth.config import Sites
from anaconda_auth.exceptions import UnknownSiteName
from anaconda_cli_base.exceptions import AnacondaConfigValidationError


@pytest.fixture(autouse=True)
def mock_openid_configuration(requests_mock: RequestMocker):
    config = AnacondaAuthConfig()
    """Mock return value of openid configuration to prevent requiring actual network calls."""
    expected = {
        "authorization_endpoint": f"https://auth.{config.domain}/api/auth/oauth2/authorize",
        "token_endpoint": f"https://auth.{config.domain}/api/auth/oauth2/token",
        "device_authorization_endpoint": f"https://auth.{config.domain}/api/auth/oauth2/device/authorize",
    }
    requests_mock.get(url=config.well_known_url, json=expected)


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
def test_docker_secret_over_default(
    tmp_path: Path, monkeypatch: MonkeyPatch, prefix: str
) -> None:
    monkeypatch.setitem(AnacondaAuthConfig.model_config, "secrets_dir", tmp_path)
    monkeypatch.setitem(AnacondaCloudConfig.model_config, "secrets_dir", tmp_path)
    key = f"{prefix}_API_KEY"
    with open(tmp_path / key.lower(), "w") as fp:
        fp.write("set-in-docker-secret")
    config = AnacondaAuthConfig()
    assert config.api_key == "set-in-docker-secret"


@pytest.mark.parametrize("prefix", ["ANACONDA_AUTH", "ANACONDA_CLOUD"])
def test_docker_secret_no_match(
    tmp_path: Path, monkeypatch: MonkeyPatch, prefix: str
) -> None:
    monkeypatch.setitem(AnacondaAuthConfig.model_config, "secrets_dir", tmp_path)
    monkeypatch.setitem(AnacondaCloudConfig.model_config, "secrets_dir", tmp_path)
    key = f"{prefix}_NONEXISTENT"
    with open(tmp_path / key.lower(), "w") as fp:
        fp.write("set-in-docker-secret")
    config = AnacondaAuthConfig()
    assert not hasattr(config, "nonexistent")


@pytest.mark.parametrize("prefix", ["ANACONDA_AUTH", "ANACONDA_CLOUD"])
def test_env_variable_over_default(monkeypatch: MonkeyPatch, prefix: str) -> None:
    monkeypatch.setenv(f"{prefix}_DOMAIN", "set-in-env")
    config = AnacondaAuthConfig()
    assert config.domain == "set-in-env"


@pytest.mark.parametrize("prefix", ["ANACONDA_AUTH", "ANACONDA_CLOUD"])
def test_env_variable_over_docker(
    tmp_path: Path, monkeypatch: MonkeyPatch, prefix: str
) -> None:
    monkeypatch.setitem(AnacondaAuthConfig.model_config, "secrets_dir", tmp_path)
    monkeypatch.setitem(AnacondaCloudConfig.model_config, "secrets_dir", tmp_path)
    key = f"{prefix}_API_KEY"
    monkeypatch.setenv(key, "set-in-env")
    with open(tmp_path / key.lower(), "w") as fp:
        fp.write("set-in-docker-secret")
    config = AnacondaAuthConfig()
    assert config.api_key == "set-in-env"


@pytest.mark.parametrize("prefix", ["ANACONDA_AUTH", "ANACONDA_CLOUD"])
def test_init_arg_over_all(
    tmp_path: Path, monkeypatch: MonkeyPatch, prefix: str
) -> None:
    monkeypatch.setitem(AnacondaAuthConfig.model_config, "secrets_dir", tmp_path)
    monkeypatch.setitem(AnacondaCloudConfig.model_config, "secrets_dir", tmp_path)
    key = f"{prefix}_DOMAIN"
    monkeypatch.setenv(key, "set-in-env")
    with open(tmp_path / key.lower(), "w") as fp:
        fp.write("set-in-docker-secret")
    config = AnacondaAuthConfig(domain="set-in-init")
    assert config.domain == "set-in-init"


def test_auth_domain_default_behavior() -> None:
    config = AnacondaAuthConfig()
    assert config.domain == config.auth_domain


def test_override_auth_domain_env_variable(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv(
        "ANACONDA_AUTH_AUTH_DOMAIN_OVERRIDE", "another-auth.anaconda.com"
    )
    config = AnacondaAuthConfig()
    assert config.auth_domain == "another-auth.anaconda.com"


@pytest.mark.usefixtures("disable_dot_env", "config_toml")
def test_default_site_no_config() -> None:
    config = AnacondaAuthSitesConfig()

    assert config.sites == Sites({"anaconda.com": AnacondaAuthConfig()})
    assert config.default_site == "anaconda.com"
    assert AnacondaAuthSitesConfig.load_site() == AnacondaAuthConfig()


@pytest.mark.usefixtures("disable_dot_env", "config_toml")
def test_unknown_site() -> None:
    config = AnacondaAuthSitesConfig()

    with pytest.raises(UnknownSiteName):
        _ = config.sites["unknown-site"]


@pytest.mark.usefixtures("disable_dot_env")
def test_default_site_with_plugin_config(config_toml: Path) -> None:
    config_toml.write_text(
        dedent(
            """\
            [plugin.auth]
            domain = "localhost"
            ssl_verify = false
            """
        )
    )
    config = AnacondaAuthSitesConfig()

    assert config.sites == Sites({"anaconda.com": AnacondaAuthConfig()})
    assert config.default_site == "anaconda.com"

    default_site = AnacondaAuthSitesConfig.load_site()
    assert default_site == AnacondaAuthConfig()
    assert default_site.domain == "localhost"
    assert not default_site.ssl_verify


@pytest.mark.usefixtures("disable_dot_env")
def test_extra_site_config(config_toml: Path) -> None:
    config_toml.write_text(
        dedent(
            """\
            [sites.local]
            domain = "localhost"
            ssl_verify = false
            """
        )
    )

    config = AnacondaAuthSitesConfig()

    local = AnacondaAuthSite(
        domain="localhost",
        ssl_verify=False,
    )

    assert config.sites == Sites({"anaconda.com": AnacondaAuthConfig(), "local": local})

    assert config.default_site == "anaconda.com"
    assert AnacondaAuthSitesConfig.load_site() == AnacondaAuthConfig()

    site = AnacondaAuthSitesConfig.load_site(site="local")
    assert site == local
    assert site.domain == "localhost"
    assert AnacondaAuthSitesConfig.load_site(
        site="local"
    ) == AnacondaAuthSitesConfig.load_site(site="localhost")


@pytest.mark.usefixtures("disable_dot_env")
def test_default_extra_site_config(config_toml: Path) -> None:
    config_toml.write_text(
        dedent(
            """\
            default_site = "local"

            [sites.local]
            domain = "localhost"
            auth_domain_override = "auth-local"
            ssl_verify = false
            """
        )
    )

    config = AnacondaAuthSitesConfig()

    local = AnacondaAuthSite(
        domain="localhost", ssl_verify=False, auth_domain_override="auth-local"
    )

    assert config.sites == Sites({"anaconda.com": AnacondaAuthConfig(), "local": local})

    assert config.sites["local"] == local
    assert config.default_site == "local"
    assert AnacondaAuthSitesConfig.load_site() == local


@pytest.mark.usefixtures("disable_dot_env")
def test_duplicate_domain_lookup_fail(config_toml: Path) -> None:
    config_toml.write_text(
        dedent(
            """\
            [sites.local1]
            domain = "localhost"
            ssl_verify = false

            [sites.local2]
            domain = "localhost"
            ssl_verify = true
            """
        )
    )

    config = AnacondaAuthSitesConfig()

    assert config.sites["local1"].ssl_verify is False
    assert config.sites["local2"].ssl_verify is True

    with pytest.raises(ValueError):
        _ = config.sites["localhost"]


@pytest.mark.usefixtures("disable_dot_env")
def test_anaconda_override_fails(config_toml: Path) -> None:
    config_toml.write_text(
        dedent(
            """\
            [sites."anaconda.com"]
            ssl_verify = false
            client_id = "foo"
            """
        )
    )

    with pytest.raises(AnacondaConfigValidationError):
        _ = AnacondaAuthSitesConfig()
