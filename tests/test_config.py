from pathlib import Path
from textwrap import dedent
from typing import Callable

import pytest
from pytest import MonkeyPatch
from pytest_mock import MockerFixture
from requests_mock import Mocker as RequestMocker

from anaconda_auth.client import BaseClient
from anaconda_auth.config import AnacondaAuthConfig
from anaconda_auth.config import AnacondaAuthSite
from anaconda_auth.config import AnacondaAuthSitesConfig
from anaconda_auth.config import AnacondaCloudConfig
from anaconda_auth.config import Sites
from anaconda_auth.exceptions import UnknownSiteName
from anaconda_cli_base.config import AnacondaConfigTomlSettingsSource


@pytest.fixture(
    autouse=True,
    params=[
        "with-device-authorization-endpoint",
        "without-device-authorization-endpoint",
    ],
)
def mock_openid_configuration(request, requests_mock: RequestMocker):
    """Mock return value of openid configuration to prevent requiring actual network calls."""
    config = AnacondaAuthConfig()
    expected = {
        "authorization_endpoint": f"https://auth.{config.domain}/api/auth/oauth2/authorize",
        "token_endpoint": f"https://auth.{config.domain}/api/auth/oauth2/token",
    }
    # This field was added to the openid configuration to support device auth, but is
    # not present on anaconda.org, so we need to test it as optional. Remove once
    # we don't need to special case this.
    if request.param == "with-device-authorization-endpoint":
        expected["device_authorization_endpoint"] = (
            f"https://auth.{config.domain}/api/auth/oauth2/device/authorize"
        )
    requests_mock.get(url=config.well_known_url, json=expected)


def test_well_known_headers(mocker: MockerFixture) -> None:
    spy = mocker.spy(BaseClient, "get")

    config = AnacondaAuthConfig()
    assert config.oidc
    spy.assert_called_once()
    assert spy.spy_return.request.headers.get("User-Agent").startswith("anaconda-auth")
    assert not spy.call_args.kwargs["auth"]


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

    assert config.sites == Sites({"anaconda.com": AnacondaAuthSite()})
    assert config.default_site == "anaconda.com"
    # The classes are not literally the same but the values are
    assert (
        AnacondaAuthSitesConfig.load_site().model_dump()
        == AnacondaAuthConfig().model_dump()
    )


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

    assert config.sites == Sites({"anaconda.com": AnacondaAuthSite()})
    assert config.default_site == "anaconda.com"

    default_site = AnacondaAuthSitesConfig.load_site()
    # this default site is identical to the AnacondaAuthConfig()
    assert default_site.model_dump() == AnacondaAuthConfig().model_dump()
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
        site="local",
        domain="localhost",
        ssl_verify=False,
    )

    assert config.sites == Sites({"local": local})

    assert config.default_site == "local"
    # This default site anaconda.com is identical to the AnacondaAuthConfig()
    assert (
        AnacondaAuthSitesConfig.load_site().model_dump()
        == AnacondaAuthConfig().model_dump()
    )

    site = AnacondaAuthSitesConfig.load_site(site="local")
    assert site.model_dump() == local.model_dump()
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
        site="local",
        domain="localhost",
        ssl_verify=False,
        auth_domain_override="auth-local",
    )

    assert config.sites == Sites({"local": local})

    assert config.sites["local"].model_dump() == local.model_dump()
    assert config.default_site == "local"
    assert AnacondaAuthSitesConfig.load_site().model_dump() == local.model_dump()


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
def test_site_inherits_from_plugin_auth_config(config_toml: Path) -> None:
    config_toml.write_text(
        dedent(
            """\
            [plugin.auth]
            domain = "foo.com"
            client_id = "foo"
            ssl_verify = false

            [sites.local]
            domain = "localhost"
            auth_domain_override = "auth-local"
            """
        )
    )

    config = AnacondaAuthSitesConfig()

    local = config.sites["local"]
    assert local.domain == "localhost"
    # [plugin.auth] provide backfills for unset values in all [sites.<name>]
    assert local.client_id == "foo"
    assert not local.ssl_verify


@pytest.mark.usefixtures("disable_dot_env")
def test_override_site_with_auth_env_vars(
    config_toml: Path, monkeypatch: MonkeyPatch
) -> None:
    config_toml.write_text(
        dedent(
            """\
            [plugin.auth]
            domain = "foo.com"
            client_id = "baz"
            ssl_verify = false

            [sites.local]
            domain = "localhost"
            auth_domain_override = "auth-local"
            client_id = "bar"
            """
        )
    )

    monkeypatch.setenv("ANACONDA_AUTH_API_KEY", "foo")

    config = AnacondaAuthSitesConfig()

    assert config.sites["local"].api_key == "foo"
    assert config.sites["local"].domain == "localhost"
    assert config.sites["local"].auth_domain_override == "auth-local"
    assert config.sites["local"].client_id == "bar"
    assert not config.sites["local"].ssl_verify

    # Finally, ANACONDA_AUTH_* env vars even override the site configuration
    monkeypatch.setenv("ANACONDA_AUTH_CLIENT_ID", "override-in-env")

    config = AnacondaAuthSitesConfig()
    local = config.sites["local"]
    assert config.sites["local"].domain == "localhost"
    assert config.sites["local"].auth_domain_override == "auth-local"
    assert local.client_id == "override-in-env"
    assert not local.ssl_verify


def test_site_default_name_and_domain() -> None:
    site = AnacondaAuthSite()
    assert site.domain == site.site == "anaconda.com"

    assert "site" not in site.model_dump()


def test_site_name_follows_domain() -> None:
    site = AnacondaAuthSite(domain="foo.bar")
    assert site.domain == site.site == "foo.bar"

    assert "site" not in site.model_dump()


def test_sites_config_dict_methods(config_toml: Path) -> None:
    config_toml.write_text(
        dedent("""\
        [sites.foobar]
        domain = "foo.bar"
    """)
    )

    expected_config = AnacondaAuthConfig()
    assert expected_config.site == "foobar"

    sites = AnacondaAuthSitesConfig()

    assert len(sites.sites) == 1
    assert list(sites.sites.keys()) == ["foobar"]
    assert "foobar" in sites.sites
    assert list(sites.sites.items()) == [("foobar", expected_config)]
    assert list(sites.sites.values()) == [expected_config]


def test_sites_add(config_toml: Path) -> None:
    config_toml.write_text(
        dedent("""\
        [plugin.auth]
        domain = "localhost"
        use_device_flow = true
    """)
    )

    sites = AnacondaAuthSitesConfig()
    config = AnacondaAuthSite(domain="foo.bar", site="foo-bar")
    sites.add(config)
    sites.write_config()
    AnacondaConfigTomlSettingsSource._cache.clear()

    sites = AnacondaAuthSitesConfig()
    expected_config = config.model_copy(update={"use_device_flow": True})

    assert sites.sites["foo-bar"].model_dump() == expected_config.model_dump()
    assert sites.sites["foo.bar"].model_dump() == expected_config.model_dump()

    assert len(sites.sites) == 2
    assert list(sites.sites.keys()) == ["anaconda.com", "foo-bar"]
    assert "foo-bar" in sites.sites

    items = list(sites.sites.items())
    assert items[1][0] == "foo-bar"
    assert items[1][1].site == expected_config.site
    assert items[1][1].model_dump() == expected_config.model_dump()

    values = list(sites.sites.values())
    assert values[1].site == expected_config.site
    assert values[1].model_dump() == expected_config.model_dump()


def test_sites_add_name(config_toml: Path) -> None:
    config_toml.write_text(
        dedent("""\
        [plugin.auth]
        domain = "localhost"
        use_device_flow = true
    """)
    )

    sites = AnacondaAuthSitesConfig()
    config = AnacondaAuthSite(domain="foo.bar", site="foo-bar")
    sites.add(config, name="foobar")
    sites.write_config()

    sites = AnacondaAuthSitesConfig()
    expected_config = config.model_copy(
        update={"use_device_flow": True, "site": "foobar"}
    )

    assert sites.sites["foobar"].model_dump() == expected_config.model_dump()
    assert sites.sites["foo.bar"].model_dump() == expected_config.model_dump()

    assert len(sites.sites) == 2
    assert list(sites.sites.keys()) == ["anaconda.com", "foobar"]
    assert "foobar" in sites.sites

    items = list(sites.sites.items())
    assert items[1][0] == "foobar"
    assert items[1][1].site == expected_config.site
    assert items[1][1].model_dump() == expected_config.model_dump()

    values = list(sites.sites.values())
    assert values[1].site == expected_config.site
    assert values[1].model_dump() == expected_config.model_dump()


def test_sites_remove_by_name(config_toml: Path) -> None:
    config_toml.write_text(
        dedent("""\
        [plugin.auth]
        domain = "localhost"
        use_device_flow = true

        [sites.foobar]
        domain = "foo.bar"
    """)
    )

    sites = AnacondaAuthSitesConfig()
    sites.remove("foobar")
    sites.write_config()

    sites = AnacondaAuthSitesConfig()

    assert len(sites.sites) == 1


def test_sites_remove_by_domain(config_toml: Path) -> None:
    config_toml.write_text(
        dedent("""\
        [plugin.auth]
        domain = "localhost"
        use_device_flow = true

        [sites.foobar]
        domain = "foo.bar"
    """)
    )

    sites = AnacondaAuthSitesConfig()
    sites.remove("foo.bar")
    sites.write_config()

    sites = AnacondaAuthSitesConfig()

    assert len(sites.sites) == 1


def test_sites_remove(config_toml: Path) -> None:
    config_toml.write_text(
        dedent("""\
        [plugin.auth]
        domain = "localhost"
        use_device_flow = true

        [sites.foobar]
        domain = "foo.bar"
    """)
    )

    sites = AnacondaAuthSitesConfig()
    sites.remove("foobar")
    sites.write_config(preserve_existing_keys=False)

    sites = AnacondaAuthSitesConfig()

    assert len(sites.sites) == 1


def test_sites_dump(config_toml: Path) -> None:
    config_toml.write_text(
        dedent(
            """\
            [sites.local]
            ssl_verify = false
            """
        )
    )

    sites = AnacondaAuthSitesConfig()
    assert not sites.sites.root["local"].ssl_verify

    sites.sites.root["local"].ssl_verify = True

    # model_dump is called twice on purpose to ensure idempotency
    assert sites.model_dump()["sites"]["local"]["ssl_verify"]
    sites.model_validate(sites.model_dump())
    assert sites.sites.root["local"].ssl_verify
    assert sites.model_dump()["sites"]["local"]["ssl_verify"]


valid_ssl_verify_with_equality = [
    (True, lambda v: v is True),
    (False, lambda v: v is False),
    ("truststore", lambda v: v == "truststore"),
    ("/path/to/cert", lambda v: v == "/path/to/cert"),
]


@pytest.mark.parametrize(
    "value,equality",
    [
        (True, lambda v: v is True),
        (False, lambda v: v is False),
        ("truststore", lambda v: v == "truststore"),
        ("/path/to/cert", lambda v: v == "/path/to/cert"),
    ],
)
def test_ssl_verify_init_values(value: str, equality: Callable) -> None:
    site = AnacondaAuthSite(ssl_verify=value)
    assert equality(site.ssl_verify)


@pytest.mark.parametrize(
    "value,equality",
    [
        ("true", lambda v: v is True),
        ("false", lambda v: v is False),
        ('"truststore"', lambda v: v == "truststore"),
        ('"/path/to/cert"', lambda v: v == "/path/to/cert"),
    ],
)
def test_ssl_verify_toml_global_values(
    config_toml: Path, value: str, equality: Callable
) -> None:
    config_toml.write_text(
        dedent(f"""\
        [plugin.auth]
        ssl_verify = {value}
    """)
    )

    config = AnacondaAuthConfig()
    assert equality(config.ssl_verify)
