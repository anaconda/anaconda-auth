from io import StringIO
from pathlib import Path
from textwrap import dedent

import pytest
from pytest_mock import MockerFixture
from rich.console import Console

from tests.conftest import CLIInvoker


@pytest.fixture
def console(mocker: MockerFixture) -> Console:
    console = Console(file=StringIO())
    mocker.patch("anaconda_auth.cli.console", console)
    yield console


def test_add_new_site(config_toml: Path, invoke_cli: CLIInvoker) -> None:
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
