from pathlib import Path
from textwrap import dedent
from typing import Generator

import pytest
import requests
from pytest import MonkeyPatch
from pytest_mock import MockerFixture
from requests_mock import Mocker as RequestMocker

from anaconda_auth.config import ANACONDA_COM_SITE
from anaconda_auth.config import AnacondaAuthConfig
from anaconda_auth.config import Site
from anaconda_auth.config import SiteConfig
from anaconda_auth.config import Sites


@pytest.fixture
def config_toml(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> Generator[Path, None, None]:
    config_file = tmp_path / "config.toml"
    monkeypatch.setenv("ANACONDA_CONFIG_TOML", str(config_file))
    yield config_file


@pytest.fixture(autouse=True)
def mock_openid_configuration(requests_mock: RequestMocker):
    config = AnacondaAuthConfig()
    """Mock return value of openid configuration to prevent requiring actual network calls."""
    expected = {
        "authorization_endpoint": f"https://auth.{config.domain}/api/auth/oauth2/authorize",
        "token_endpoint": f"https://auth.{config.domain}/api/auth/oauth2/token",
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
def test_env_variable_over_default(monkeypatch: MonkeyPatch, prefix: str) -> None:
    monkeypatch.setenv(f"{prefix}_DOMAIN", "set-in-env")
    config = AnacondaAuthConfig()
    assert config.domain == "set-in-env"


@pytest.mark.parametrize("prefix", ["ANACONDA_AUTH", "ANACONDA_CLOUD"])
def test_init_arg_over_env_variable(monkeypatch: MonkeyPatch, prefix: str) -> None:
    monkeypatch.setenv(f"{prefix}_DOMAIN", "set-in-env")
    config = AnacondaAuthConfig(domain="set-in-init")
    assert config.domain == "set-in-init"


def test_override_auth_domain_env_variable(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv(
        "ANACONDA_AUTH_AUTH_DOMAIN_OVERRIDE", "another-auth.anaconda.com"
    )
    config = AnacondaAuthConfig()
    assert config.auth_domain == "another-auth.anaconda.com"


@pytest.mark.usefixtures("disable_dot_env")
def test_default_site_no_config() -> None:
    config = SiteConfig()

    assert config.sites == Sites({"anaconda.com": ANACONDA_COM_SITE})
    assert config.default_site == "anaconda.com"
    assert config.get_default_site() == ANACONDA_COM_SITE


@pytest.mark.usefixtures("disable_dot_env")
def test_extra_site_config(config_toml: Path) -> None:
    config_toml.write_text(
        dedent("""\
        [sites.local]
        domain = "localhost"
        ssl_verify = false
        auth = {"domain" = "auth-test"}
    """)
    )

    config = SiteConfig()

    local = Site(
        domain="localhost",
        ssl_verify=False,
        extra_headers=None,
        api_key=None,
        auth=AnacondaAuthConfig(domain="auth-test"),
    )

    assert config.sites == Sites({"anaconda.com": ANACONDA_COM_SITE, "local": local})

    assert config.sites["local"] == local
    assert config.default_site == "anaconda.com"
    assert config.get_default_site() == ANACONDA_COM_SITE


@pytest.mark.usefixtures("disable_dot_env")
def test_default_extra_site_config(config_toml: Path) -> None:
    config_toml.write_text(
        dedent("""\
        default_site = "local"

        [sites.local]
        domain = "localhost"
        ssl_verify = false
        auth = {"domain" = "auth-test"}

    """)
    )

    config = SiteConfig()

    local = Site(
        domain="localhost",
        ssl_verify=False,
        extra_headers=None,
        api_key=None,
        auth=AnacondaAuthConfig(domain="auth-test"),
    )

    assert config.sites == Sites({"anaconda.com": ANACONDA_COM_SITE, "local": local})

    assert config.sites["local"] == local
    assert config.default_site == "local"
    assert config.get_default_site() == local


@pytest.mark.usefixtures("disable_dot_env")
def test_anaconda_override(config_toml: Path) -> None:
    config_toml.write_text(
        dedent("""\
        [sites."anaconda.com"]
        ssl_verify = false
        auth = {"ssl_verify" = false}

    """)
    )

    config = SiteConfig()

    assert config.sites == Sites(
        {
            "anaconda.com": Site(
                domain="anaconda.com",
                ssl_verify=False,
                auth=AnacondaAuthConfig(ssl_verify=False),
            )
        }
    )
