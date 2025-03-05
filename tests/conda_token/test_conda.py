import json
from textwrap import dedent

import pytest
from conda.cli.python_api import Commands
from conda.cli.python_api import run_command
from packaging.version import parse

from anaconda_auth._conda.repo_config import CONDA_VERSION


def json_skip_preamble(text):
    """
    Ignore text before the first line starting with {
    """
    capture = False
    captured = []
    for line in text.splitlines():
        if line.strip().startswith(("{", "[")):
            capture = True
        if capture:
            captured.append(line)
    return json.loads("\n".join(captured))


def test_skip_garbage():
    lines = dedent(
        """
        Random text
        Error message
         {"foo":
        "bar"
        }
        """
    )

    lines2 = dedent(
        """
        Unexpected warning
         [ 1 ]
        """
    )
    assert json_skip_preamble(lines) == {"foo": "bar"}
    assert json_skip_preamble(lines2) == [1]


@pytest.mark.skipif(
    CONDA_VERSION < parse("4.10.1"),
    reason="Signature verification was added in Conda 4.10.1",
)
@pytest.mark.skipif(
    parse("23.9") <= CONDA_VERSION < parse("23.10"),
    reason="metadata_signature_status missing in conda 23.9",
)
@pytest.mark.skipif(
    CONDA_VERSION >= parse("24.1"),
    reason="conda >=24.1 delays signature checks to after a solve",
)
def test_conda_search_rope_signed(set_secret_token_with_signing):
    stdout, _, _ = run_command(Commands.SEARCH, "--spec", "rope=0.18.0=py_0", "--json")
    try:
        rope = json_skip_preamble(stdout)["rope"][0]
    except json.JSONDecodeError:
        print("Could not decode", stdout)
        raise
    # conda 23.x appears to have changed this value to a string
    assert rope.get("metadata_signature_status") in (
        0,
        "(INFO: package metadata is signed by Anaconda and trusted)",
    ), rope

    stdout, _, _ = run_command(
        Commands.SEARCH, "--spec", "conda-forge::rope=0.18.0=pyhd3deb0d_0", "--json"
    )
    try:
        rope = json_skip_preamble(stdout)["rope"][0]
    except json.JSONDecodeError:
        print("Could not decode", stdout)
        raise
    # conda 23.x appears to omit the key if unsigned
    assert "metadata_signature_status" not in rope or rope.get(
        "metadata_signature_status"
    ) in (
        -1,
        "(WARNING: metadata signature verification failed)",
    ), rope


@pytest.mark.integration
def test_conda_search_rope(set_secret_token):
    if CONDA_VERSION < parse("4.4"):
        stdout, _, _ = run_command(
            Commands.SEARCH, "--spec", "rope=0.18.0=py_0", "--json"
        )
    else:
        stdout, _, _ = run_command(Commands.SEARCH, "rope==0.18.0=py_0", "--json")
    try:
        rope = json_skip_preamble(stdout)["rope"][0]
    except json.JSONDecodeError:
        print("Could not decode", stdout)
        raise
    assert rope["url"].startswith("https://repo.anaconda.cloud/repo/main/noarch")


@pytest.mark.integration
def test_conda_install_rope(set_secret_token, uninstall_rope):
    install_args = (Commands.INSTALL, "rope", "-y")
    # is libmamba-solver using its own network code, not adding the token here?
    if parse("23.10") < CONDA_VERSION < parse("24.1"):
        install_args = install_args + ("--solver=classic",)
    run_command(*install_args)

    if CONDA_VERSION < parse("4.6"):
        stdout, _, _ = run_command(Commands.LIST, "--explicit")
        pkgs = stdout.splitlines()
        for p in pkgs:
            if "rope" in p:
                assert p.startswith("https://repo.anaconda.cloud/repo/main")
    else:
        stdout, _, _ = run_command(
            Commands.LIST, "rope", "--show-channel-urls", "--json"
        )
        try:
            rope = json_skip_preamble(stdout)[0]
        except (json.JSONDecodeError, TypeError):
            print("Could not decode", stdout)
            raise
        assert rope["base_url"] == "https://repo.anaconda.cloud/repo/main"


@pytest.mark.integration
def test_conda_install_with_conda_forge(set_secret_token, uninstall_rope):
    run_command(
        Commands.INSTALL,
        "-c",
        "defaults",
        "-c",
        "conda-forge",
        "rope",
        "conda-forge-pinning",
        "-y",
    )

    if CONDA_VERSION < parse("4.6"):
        stdout, _, _ = run_command(Commands.LIST, "--explicit")
        pkgs = stdout.splitlines()
        for p in pkgs:
            if "rope" in p:
                assert p.startswith("https://repo.anaconda.cloud/repo/main")
            if "conda-forge-pinning" in p:
                assert p.startswith("https://conda.anaconda.org/conda-forge")
    else:
        stdout, _, _ = run_command(
            Commands.LIST, "rope", "--show-channel-urls", "--json"
        )
        try:
            rope = json_skip_preamble(stdout)[0]
        except json.JSONDecodeError:
            print("Could not decode", stdout)
            raise
        assert rope["base_url"] == "https://repo.anaconda.cloud/repo/main"

        stdout, _, _ = run_command(
            Commands.LIST, "conda-forge-pinning", "--show-channel-urls", "--json"
        )
        try:
            conda_forge_pinning = json_skip_preamble(stdout)[0]
        except json.JSONDecodeError:
            print("Could not decode", stdout)
            raise
        assert (
            conda_forge_pinning["base_url"] == "https://conda.anaconda.org/conda-forge"
        )
