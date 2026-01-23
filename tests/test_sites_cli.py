from io import StringIO
from pathlib import Path
from textwrap import dedent
from typing import Callable

import pytest
from pytest_mock import MockerFixture
from rich.console import Console

from anaconda_auth.config import AnacondaAuthSitesConfig
from tests.conftest import CLIInvoker


@pytest.fixture
def console(mocker: MockerFixture) -> Console:
    console = Console(file=StringIO())
    mocker.patch("anaconda_auth.cli.console", console)
    yield console


def test_add_new_site_removes_anaconda_com(
    config_toml: Path, invoke_cli: CLIInvoker
) -> None:
    assert not config_toml.exists()

    result = invoke_cli(
        ["sites", "add", "--name", "short-name", "--domain", "foo.local", "--yes"]
    )
    assert result.exit_code == 0

    assert config_toml.read_text() == dedent(
        """\
        default_site = "short-name"

        [sites.short-name]
        domain = "foo.local"
        """
    )


def test_add_new_site_without_name(config_toml: Path, invoke_cli: CLIInvoker) -> None:
    assert not config_toml.exists()

    result = invoke_cli(["sites", "add", "--domain", "foo.local", "--yes"])
    assert result.exit_code == 0

    assert config_toml.read_text() == dedent(
        """\
        default_site = "foo.local"

        [sites."foo.local"]
        domain = "foo.local"
        """
    )


def test_add_new_site_without_domain(config_toml: Path, invoke_cli: CLIInvoker) -> None:
    assert not config_toml.exists()

    result = invoke_cli(["sites", "add", "--name", "foo", "--yes"])
    assert result.exit_code == 1
    assert "You must supply at least --domain" in result.stdout


def test_add_existing_name(config_toml: Path, invoke_cli: CLIInvoker) -> None:
    config_toml.write_text(
        dedent(
            """\
            default_site = "foo"

            [sites.foo]
            domain = "foo.local"
            ssl_verify = false
            """
        )
    )

    result = invoke_cli(
        ["sites", "add", "--name", "foo", "--domain", "foo.bar", "--yes"]
    )
    assert result.exit_code == 1

    assert "A site with name foo already exists" in result.stdout


@pytest.mark.parametrize("flag", ["extra-headers", "proxy-servers", "keyring"])
def test_add_new_site_bad_json(
    flag: str, config_toml: Path, invoke_cli: CLIInvoker
) -> None:
    assert not config_toml.exists()

    result = invoke_cli(
        [
            "sites",
            "add",
            "--domain",
            "foo.local",
            f"--{flag}",
            "{'single': 'quoted'}",
            "--yes",
        ]
    )
    assert result.exit_code == 1
    assert "could not be parsed as JSON" in result.stdout


@pytest.mark.parametrize("flag", ["api-key", "keyring"])
def test_add_site_insecure_flag(
    flag: str, config_toml: Path, invoke_cli: CLIInvoker
) -> None:
    assert not config_toml.exists()

    result = invoke_cli(["sites", "add", "--domain", "foo.bar", f"--{flag}", "value"])

    assert "may not be secure" in result.stdout


@pytest.mark.parametrize(
    "ssl_verify,truststore,equivalence",
    [
        pytest.param("", "", lambda ssl_verify: ssl_verify is True, id="unset"),
        pytest.param(
            "--ssl-verify", "", lambda ssl_verify: ssl_verify is True, id="ssl-verify"
        ),
        pytest.param(
            "--no-ssl-verify",
            "",
            lambda ssl_verify: ssl_verify is False,
            id="no-ssl-verify",
        ),
        pytest.param(
            "",
            "--use-truststore",
            lambda ssl_verify: ssl_verify == "truststore",
            id="use-truststore",
        ),
        pytest.param(
            "--ssl-verify",
            "--use-truststore",
            lambda ssl_verify: ssl_verify == "truststore",
            id="verify-use-truststore",
        ),
        pytest.param(
            "",
            "--no-use-truststore",
            lambda ssl_verify: ssl_verify is True,
            id="no-use-truststore",
        ),
    ],
)
def test_ssl_verify_truststore_valid(
    ssl_verify: str,
    truststore: str,
    equivalence: Callable,
    config_toml: Path,
    invoke_cli: CLIInvoker,
) -> None:
    assert not config_toml.exists()

    cmd = [
        "sites",
        "add",
        "--domain",
        "foo.bar",
        "--yes",
    ]

    if ssl_verify:
        cmd.append(ssl_verify)
    if truststore:
        cmd.append(truststore)

    result = invoke_cli(cmd)

    assert result.exit_code == 0

    config = AnacondaAuthSitesConfig.load_site("foo.bar")
    assert equivalence(config.ssl_verify)


@pytest.mark.parametrize(
    "ssl_verify,truststore,exit_code,msg",
    [
        pytest.param(
            "--no-ssl-verify",
            "--use-truststore",
            1,
            "Cannot set both",
            id="no-verify-use-truststore",
        ),
    ],
)
def test_ssl_verify_truststore_invalid(
    ssl_verify: str,
    truststore: str,
    exit_code: int,
    msg: str,
    config_toml: Path,
    invoke_cli: CLIInvoker,
) -> None:
    assert not config_toml.exists()

    cmd = [
        "sites",
        "add",
        "--domain",
        "foo.bar",
        "--yes",
    ]

    if ssl_verify:
        cmd.append(ssl_verify)
    if truststore:
        cmd.append(truststore)

    result = invoke_cli(cmd)

    assert result.exit_code == exit_code
    assert msg in result.stdout


def test_add_new_site_keep_anaconda_com(
    config_toml: Path, invoke_cli: CLIInvoker
) -> None:
    assert not config_toml.exists()

    result = invoke_cli(
        [
            "sites",
            "add",
            "--name",
            "short-name",
            "--domain",
            "foo.local",
            "--no-remove-anaconda-com",
            "--yes",
        ]
    )
    assert result.exit_code == 0

    assert config_toml.read_text() == dedent(
        """\
        default_site = "anaconda.com"

        [sites."anaconda.com"]

        [sites.short-name]
        domain = "foo.local"
        """
    )


def test_modify_keeps_ssl_verify_false(
    config_toml: Path, invoke_cli: CLIInvoker
) -> None:
    config_toml.write_text(
        dedent(
            """\
            default_site = "short-name"

            [sites.short-name]
            domain = "foo.local"
            ssl_verify = false
            """
        )
    )

    result = invoke_cli(
        ["sites", "modify", "--name", "short-name", "--use-device-flow", "--yes"]
    )
    assert result.exit_code == 0

    assert config_toml.read_text() == dedent(
        """\
        default_site = "short-name"

        [sites.short-name]
        domain = "foo.local"
        ssl_verify = false
        use_device_flow = true
        """
    )


def test_swap_default_keeps_ssl_verify_false(
    config_toml: Path, invoke_cli: CLIInvoker
) -> None:
    config_toml.write_text(
        dedent(
            """\
            default_site = "s2"

            [sites.s1]
            domain = "foo.bar"
            ssl_verify = false

            [sites.s2]
            domain = "foo.baz"
            """
        )
    )

    result = invoke_cli(["sites", "modify", "--name", "s1", "--default", "--yes"])
    assert result.exit_code == 0

    assert config_toml.read_text() == dedent(
        """\
        default_site = "s1"

        [sites.s1]
        domain = "foo.bar"
        ssl_verify = false

        [sites.s2]
        domain = "foo.baz"
        """
    )


def test_modify_lookup_domain(config_toml: Path, invoke_cli: CLIInvoker) -> None:
    config_toml.write_text(
        dedent(
            """\
            default_site = "foo"

            [sites.foo]
            domain = "foo.local"
            ssl_verify = false

            [sites.bar]
            domain = "bar.local"
            """
        )
    )

    result = invoke_cli(
        ["sites", "modify", "--domain", "foo.local", "--use-device-flow", "--yes"]
    )
    assert result.exit_code == 0

    assert config_toml.read_text() == dedent(
        """\
        default_site = "foo"

        [sites.foo]
        domain = "foo.local"
        ssl_verify = false
        use_device_flow = true

        [sites.bar]
        domain = "bar.local"
        """
    )


def test_modify_lookup_duplicate_domain(
    config_toml: Path, invoke_cli: CLIInvoker
) -> None:
    config_toml.write_text(
        dedent(
            """\
            default_site = "foo"

            [sites.foo]
            domain = "foo.local"
            ssl_verify = false

            [sites.bar]
            domain = "foo.local"
            """
        )
    )

    result = invoke_cli(
        ["sites", "modify", "--domain", "foo.local", "--use-device-flow", "--yes"]
    )
    assert result.exit_code == 1

    assert "matches more than one configured site" in result.stdout


@pytest.mark.parametrize("flag", ["name", "domain"])
def test_modify_lookup_missing(
    flag: str, config_toml: Path, invoke_cli: CLIInvoker
) -> None:
    config_toml.write_text(
        dedent(
            """\
            default_site = "foo"

            [sites.foo]
            domain = "foo.local"
            ssl_verify = false

            [sites.bar]
            domain = "foo.local"
            """
        )
    )

    result = invoke_cli(
        ["sites", "modify", f"--{flag}", "foo.bar", "--use-device-flow", "--yes"]
    )
    assert result.exit_code == 1

    assert "The site or domain foo.bar has not been configured" in result.stdout
