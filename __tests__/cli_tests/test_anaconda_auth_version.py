# This test verified the anaconda auth version with both long and short flags.

import pytest
import shutil
from src.common.cli_utils import capture
from src.common.defaults import (
    CLI_SUBCOMMAND,
    VERSION_FLAGS,
    ANACONDA_AUTH_VERSION,
)

@pytest.mark.integration
@pytest.mark.parametrize(
    "command",
    [
        ("anaconda auth --version", "0.8.5"),
        ("anaconda auth -V", "0.8.5"),
    ],
    ids=["longflag", "shortflag"]
)
def test_anaconda_auth_reports_exact_version(command, ensureConda):
    """
    Ensure `anaconda auth --version` and `-V` succeed and report version 0.8.5.
   
    Args:
        command (str): The command to execute (--version or -V)
        expected_version (str): The expected version string -> this is something you may want to consider as part of the input as well
        ensureConda (fixture): Ensures Conda is properly installed
   
    Raises:
        AssertionError: If version check fails or command execution fails
    """
    # Extract command and expected version from parameterized input
    cmd, expected_version = command
   
    # Fail fast if `anaconda` isn't on PATH
    anaconda_path = shutil.which("anaconda")
    assert anaconda_path, "`anaconda` binary not in PATH — please install anaconda-cli"
   
    # Run and capture
    output_bytes, exit_code = capture(cmd)
   
    # Must exit 0
    assert exit_code == 0, (
        f"{cmd!r} exited with code {exit_code}\n"
        f"stdout:\n{output_bytes.decode()}\n"
        f"CLI binary: {anaconda_path}"
    )
   
    # Output should include the exact version string
    output_text = output_bytes.decode().strip()
    assert ANACONDA_AUTH_VERSION in output_text, (
        f"Expected version '{ANACONDA_AUTH_VERSION}' in output of {cmd!r}, got:\n{output_text}"
    )