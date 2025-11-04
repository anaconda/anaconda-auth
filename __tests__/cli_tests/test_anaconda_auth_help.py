# This test verifies the anaconda auth help command output.

import pytest
import shutil
import logging
from src.common.cli_utils import capture
from src.common.defaults import CLI_SUBCOMMAND

logger = logging.getLogger(__name__)

# Expected help content constants
EXPECTED_USAGE_TEXT = "usage: anaconda auth"
EXPECTED_OPTIONS = ["--version", "--help"]
EXPECTED_VERSION_FLAGS = ["-v", "-V"]  # Either short version flag should be present
EXPECTED_COMMANDS = ["api-key", "login", "logout", "whoami"]

@pytest.mark.integration
def test_anaconda_auth_help_contains_expected_sections(ensureConda):
    """
    Ensure `anaconda auth --help` shows all required sections and commands.
   
    Verifies the help output contains:
    • A usage header with 'usage: anaconda auth'
    • Options: --version, -V (or -v), and --help
    • Commands: api-key, login, logout, whoami
   
    Args:
        ensureConda (fixture): Ensures Conda and anaconda-cli are properly installed
       
    Raises:
        AssertionError: If help command fails or expected content is missing
    """
    # Fail fast if `anaconda` isn't on PATH
    anaconda_path = shutil.which("anaconda")
    assert anaconda_path, "`anaconda` binary not in PATH — please install anaconda-cli"
   
    # Run the help command and capture its output
    help_command = f"{CLI_SUBCOMMAND} --help"
    output_bytes, exit_code = capture(help_command)
   
    assert exit_code == 0, (
        f"{help_command!r} failed: exit code {exit_code}\n"
        f"stdout:\n{output_bytes.decode()}\n"
        f"CLI binary: {anaconda_path}"
    )
   
    help_text = output_bytes.decode().lower()
   
    # Verify usage header
    assert EXPECTED_USAGE_TEXT.lower() in help_text, (
        f"Missing usage header '{EXPECTED_USAGE_TEXT}' in help output"
    )
   
    # Verify required options
    for option in EXPECTED_OPTIONS:
        assert option in help_text, (
            f"Missing required option '{option}' in help output"
        )
   
    # Verify at least one version flag is present
    version_flag_found = any(flag in help_text for flag in EXPECTED_VERSION_FLAGS)
    assert version_flag_found, (
        f"Missing version flag. Expected one of {EXPECTED_VERSION_FLAGS} in help output"
    )
   
    # Verify all expected commands
    for command in EXPECTED_COMMANDS:
        assert command in help_text, (
            f"Missing required command '{command}' in help output"
        )
   
    logger.info("✅ Help command verification completed successfully!")
    logger.info(f"   → Found usage header: '{EXPECTED_USAGE_TEXT}'")
    logger.info(f"   → Found all required options: {EXPECTED_OPTIONS}")
    logger.info(f"   → Found version flag from: {EXPECTED_VERSION_FLAGS}")
    logger.info(f"   → Found all required commands: {EXPECTED_COMMANDS}")