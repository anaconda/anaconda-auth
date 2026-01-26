import json
import os
from io import StringIO
from pathlib import Path
from textwrap import dedent
from typing import Any
from typing import Callable
from typing import Dict

import pytest
from pytest import MonkeyPatch
from pytest_mock import MockerFixture
from rich.console import Console

from anaconda_auth.config import AnacondaAuthSitesConfig
from tests.conftest import CLIInvoker


def is_windows() -> bool:
    return os.name == "nt"


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


def test_add_new_site_no_removes_anaconda_com(
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


def test_add_new_default_site_no_removes_anaconda_com(
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
            "--default",
            "--no-remove-anaconda-com",
            "--yes",
        ]
    )
    assert result.exit_code == 0

    assert config_toml.read_text() == dedent(
        """\
        default_site = "short-name"

        [sites."anaconda.com"]

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


def test_add_site_protect_secrets(
    config_toml: Path, invoke_cli: CLIInvoker, monkeypatch: MonkeyPatch
) -> None:
    assert not config_toml.exists()

    if is_windows():
        value = "true"

        def equivalence(value: str) -> bool:
            return value is True
    else:
        cert_path = config_toml.parent / "cert.pem"
        cert_path.touch()
        value = str(cert_path)

        def equivalence(value: bool) -> bool:
            return value == str(cert_path)

    monkeypatch.setenv("ANACONDA_AUTH_API_KEY", "in-env-var")
    monkeypatch.setenv("CONDA_SSL_VERIFY", value)

    result = invoke_cli(["sites", "add", "--domain", "foo.local", "--yes"])
    assert result.exit_code == 0

    assert config_toml.read_text() == dedent(
        """\
        default_site = "foo.local"

        [sites."foo.local"]
        domain = "foo.local"
        """
    )

    result = invoke_cli(["sites", "show", "--show-hidden", "foo.local"])
    data: Dict[str, Any] = json.loads(result.stdout)
    assert data.get("api_key", "") == "in-env-var"
    assert equivalence(data.get("ssl_verify"))


def test_add_new_site_dry_run(config_toml: Path, invoke_cli: CLIInvoker) -> None:
    assert not config_toml.exists()

    result = invoke_cli(["sites", "add", "--domain", "foo.local", "--dry-run"])
    assert result.exit_code == 0
    assert '+[sites."foo.local"]'
    assert not config_toml.exists()


def test_add_new_site_no_confirm(config_toml: Path, invoke_cli: CLIInvoker) -> None:
    assert not config_toml.exists()

    result = invoke_cli(["sites", "add", "--domain", "foo.local"], input="n")
    assert result.exit_code == 0
    assert '+[sites."foo.local"]'
    assert not config_toml.exists()


def test_add_new_site_confirm(config_toml: Path, invoke_cli: CLIInvoker) -> None:
    assert not config_toml.exists()

    result = invoke_cli(["sites", "add", "--domain", "foo.local"], input="y")
    assert result.exit_code == 0
    assert '+[sites."foo.local"]'

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
    assert result.exit_code == 2
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
            2,
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


def test_modify_requires_name_or_domain(
    config_toml: Path, invoke_cli: CLIInvoker
) -> None:
    assert not config_toml.exists()

    result = invoke_cli(["sites", "modify", "--no-ssl-verify"])
    assert result.exit_code == 2
    assert (
        "You must supply at least one of --domain or --name to modify a site"
        in result.stdout
    )


def test_modify_protect_secrets(
    config_toml: Path, invoke_cli: CLIInvoker, monkeypatch: MonkeyPatch
) -> None:
    if is_windows():
        value = "true"

        def equivalence(value: str) -> bool:
            return value is True
    else:
        cert_path = config_toml.parent / "cert.pem"
        cert_path.touch()
        value = str(cert_path)

        def equivalence(value: bool) -> bool:
            return value == str(cert_path)

    monkeypatch.setenv("ANACONDA_AUTH_API_KEY", "in-env-var")
    monkeypatch.setenv("CONDA_SSL_VERIFY", value)
    config_toml.write_text(
        dedent(
            """\
            default_site = "short-name"

            [sites.short-name]
            domain = "foo.local"
            """
        )
    )

    result = invoke_cli(["sites", "show", "--show-hidden", "short-name"])
    data: Dict[str, Any] = json.loads(result.stdout)
    assert data.get("api_key", "") == "in-env-var"
    assert equivalence(data.get("ssl_verify"))

    result = invoke_cli(
        ["sites", "modify", "--name", "short-name", "--use-device-flow", "--yes"]
    )
    assert result.exit_code == 0

    assert config_toml.read_text() == dedent(
        """\
        default_site = "short-name"

        [sites.short-name]
        domain = "foo.local"
        use_device_flow = true
        """
    )

    result = invoke_cli(["sites", "show", "--show-hidden", "short-name"])
    data: Dict[str, Any] = json.loads(result.stdout)
    assert data.get("api_key", "") == "in-env-var"
    assert equivalence(data.get("ssl_verify"))


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


def test_remove_fails(config_toml: Path, invoke_cli: CLIInvoker) -> None:
    assert not config_toml.exists()

    result = invoke_cli(["sites", "remove", "nope"])

    assert result.exit_code == 1
    assert "The site or domain nope has not been configured" in result.stdout


def test_cannot_remove_anaconda_com(config_toml: Path, invoke_cli: CLIInvoker) -> None:
    assert not config_toml.exists()

    result = invoke_cli(["sites", "remove", "anaconda.com"])

    assert result.exit_code == 1
    assert (
        "anaconda.com is the only configured site and cannot be removed"
        in result.stdout
    )


def test_cannot_remove_only_site(config_toml: Path, invoke_cli: CLIInvoker) -> None:
    config_toml.write_text(
        dedent("""\
            default_site = "foo"

            [sites.foo]

        """)
    )

    result = invoke_cli(["sites", "remove", "foo"])

    assert result.exit_code == 1
    assert "foo is the only configured site and cannot be removed" in result.stdout


def test_remove_default_site(config_toml: Path, invoke_cli: CLIInvoker) -> None:
    config_toml.write_text(
        dedent("""\
            default_site = "foo"

            [sites.bar]

            [sites.foo]

            [sites.baz]

        """)
    )

    result = invoke_cli(["sites", "remove", "foo", "--yes"])
    assert result.exit_code == 0

    assert config_toml.read_text() == dedent(
        """\
            default_site = "bar"

            [sites.bar]

            [sites.baz]
        """
    )


def test_remove_non_default_site(config_toml: Path, invoke_cli: CLIInvoker) -> None:
    config_toml.write_text(
        dedent("""\
            default_site = "foo"

            [sites.bar]

            [sites.foo]

            [sites.baz]

        """)
    )

    result = invoke_cli(["sites", "remove", "bar", "--yes"])
    assert result.exit_code == 0

    assert config_toml.read_text() == dedent(
        """\
            default_site = "foo"

            [sites.foo]

            [sites.baz]
        """
    )


def test_remove_dry_run(config_toml: Path, invoke_cli: CLIInvoker) -> None:
    contents = dedent("""\
            default_site = "foo"

            [sites.bar]

            [sites.foo]

            [sites.baz]

    """)
    config_toml.write_text(contents)

    result = invoke_cli(["sites", "remove", "bar", "--dry-run"])
    assert result.exit_code == 0
    assert "-[sites.bar]" in result.stdout

    assert config_toml.read_text() == contents


def test_remove_confirm(config_toml: Path, invoke_cli: CLIInvoker) -> None:
    contents = dedent("""\
            default_site = "foo"

            [sites.bar]

            [sites.foo]

            [sites.baz]

    """)
    config_toml.write_text(contents)

    result = invoke_cli(["sites", "remove", "bar"], input="y")
    assert result.exit_code == 0

    assert "-[sites.bar]" in result.stdout

    assert config_toml.read_text() == dedent(
        """\
            default_site = "foo"

            [sites.foo]

            [sites.baz]
        """
    )


def test_remove_no_confirm(config_toml: Path, invoke_cli: CLIInvoker) -> None:
    contents = dedent("""\
            default_site = "foo"

            [sites.bar]

            [sites.foo]

            [sites.baz]

    """)
    config_toml.write_text(contents)

    result = invoke_cli(["sites", "remove", "bar"], input="n")
    assert result.exit_code == 0

    assert "-[sites.bar]" in result.stdout

    assert config_toml.read_text() == contents
