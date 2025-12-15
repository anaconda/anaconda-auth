from pathlib import Path
from textwrap import dedent

import pytest
from pytest import MonkeyPatch

from anaconda_auth.config import AnacondaAuthConfig

conda = pytest.importorskip("conda")


@pytest.mark.usefixtures("disable_dot_env")
def test_conda_context_apply_to_default_site(
    condarc_path: Path,
    config_toml: Path,
) -> None:
    condarc_path.write_text(
        dedent("""\
        ssl_verify: false
        proxy_servers:
            http: 127.0.0.1:80
            https: 127.0.0.1:80
    """)
    )
    conda.base.context.reset_context()

    config = AnacondaAuthConfig()
    assert config.proxy_servers == {"http": "127.0.0.1:80", "https": "127.0.0.1:80"}
    assert not config.ssl_verify


@pytest.mark.usefixtures("disable_dot_env")
def test_conda_context_ssl_verify_cert_path(
    condarc_path: Path,
    config_toml: Path,
) -> None:
    condarc_path.write_text(
        dedent(
            """\
            ssl_verify: /path/to/cert.pem
            """
        )
    )
    conda.base.context.reset_context()

    config = AnacondaAuthConfig()
    assert config.ssl_verify == "/path/to/cert.pem"


@pytest.mark.usefixtures("disable_dot_env")
def test_conda_context_priority_config_toml(
    condarc_path: Path,
    config_toml: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    condarc_path.write_text(
        dedent("""\
        ssl_verify: false
        proxy_servers:
            http: 127.0.0.1:80
            https: 127.0.0.1:80
    """)
    )
    conda.base.context.reset_context()

    config_toml.write_text(
        dedent("""\
        [plugin.auth]
        ssl_verify = true
    """)
    )

    # ~/.anaconda/config.toml overrides inherited settings
    default = AnacondaAuthConfig()
    assert default.ssl_verify
    assert default.proxy_servers == {"http": "127.0.0.1:80", "https": "127.0.0.1:80"}
    assert default.client_cert is None
    assert default.client_cert_key is None

    # Anaconda Auth secrets and env vars are higher priority
    monkeypatch.setenv("ANACONDA_AUTH_CLIENT_CERT", "/path/to/cert")
    default = AnacondaAuthConfig()
    assert default.ssl_verify
    assert default.proxy_servers == {"http": "127.0.0.1:80", "https": "127.0.0.1:80"}
    assert default.client_cert == "/path/to/cert"
    assert default.client_cert_key is None

    # Finally, init kwargs are highest priority
    yes_verified = AnacondaAuthConfig(ssl_verify=False, proxy_servers=None)
    assert not yes_verified.ssl_verify
    assert yes_verified.proxy_servers is None
    assert yes_verified.client_cert == "/path/to/cert"
    assert yes_verified.client_cert_key is None


@pytest.mark.usefixtures("disable_dot_env")
def test_conda_context_priority_sites(
    condarc_path: Path,
    config_toml: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    condarc_path.write_text(
        dedent("""\
        ssl_verify: false
        proxy_servers:
            http: 127.0.0.1:80
            https: 127.0.0.1:80
    """)
    )
    conda.base.context.reset_context()

    config_toml.write_text(
        dedent("""\
        default_site = "anaconda.com"
        [sites."anaconda.com"]

        [sites.verified]
        ssl_verify = true

        [sites.proxied.proxy_servers]
        http = "proxy:80"
        https = "proxy:80"
    """)
    )

    # In the absence of an explicit setting inherit from conda context
    default = AnacondaAuthConfig()
    assert not default.ssl_verify
    assert default.proxy_servers == {"http": "127.0.0.1:80", "https": "127.0.0.1:80"}
    assert default.client_cert is None
    assert default.client_cert_key is None

    # ~/.anaconda/config.toml overrides inherited settings
    verified = AnacondaAuthConfig(site="verified")
    assert verified.ssl_verify
    assert verified.proxy_servers == {"http": "127.0.0.1:80", "https": "127.0.0.1:80"}
    assert verified.client_cert is None
    assert verified.client_cert_key is None

    proxied = AnacondaAuthConfig(site="proxied")
    assert not proxied.ssl_verify
    assert proxied.proxy_servers == {"http": "proxy:80", "https": "proxy:80"}
    assert proxied.client_cert is None
    assert proxied.client_cert_key is None

    # Anaconda Auth secrets and env vars are higher priority
    monkeypatch.setenv("ANACONDA_AUTH_SSL_VERIFY", "true")
    monkeypatch.setenv("ANACONDA_AUTH_CLIENT_CERT", "/path/to/cert")

    default = AnacondaAuthConfig()
    assert default.ssl_verify
    assert default.proxy_servers == {"http": "127.0.0.1:80", "https": "127.0.0.1:80"}
    assert default.client_cert == "/path/to/cert"
    assert default.client_cert_key is None

    verified = AnacondaAuthConfig(site="verified")
    assert verified.ssl_verify
    assert verified.proxy_servers == {"http": "127.0.0.1:80", "https": "127.0.0.1:80"}
    assert verified.client_cert == "/path/to/cert"
    assert verified.client_cert_key is None

    proxied = AnacondaAuthConfig(site="proxied")
    assert proxied.ssl_verify
    assert proxied.proxy_servers == {"http": "proxy:80", "https": "proxy:80"}
    assert proxied.client_cert == "/path/to/cert"
    assert proxied.client_cert_key is None

    # Finally, init kwargs are highest priority
    monkeypatch.delenv("ANACONDA_AUTH_SSL_VERIFY")
    yes_verified = AnacondaAuthConfig(ssl_verify=True, proxy_servers=None)
    assert yes_verified.ssl_verify
    assert yes_verified.proxy_servers is None
    assert yes_verified.client_cert == "/path/to/cert"
    assert yes_verified.client_cert_key is None
