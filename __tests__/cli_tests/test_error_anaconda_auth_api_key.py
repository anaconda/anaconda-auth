# This test verifies the `anaconda auth api-key` command when the user is not logged in.
import logging
import pytest
import shutil
from src.common.cli_utils import capture
from src.common.defaults import CLI_SUBCOMMAND

logger = logging.getLogger(__name__)

@pytest.mark.integration
def test_anaconda_auth_api_key_requires_login(ensureConda):
    """
    Test that `anaconda auth api-key` shows appropriate error when user is not logged in.
   
    Expected behavior:
    - Command should fail with non-zero exit code
    - Should display login-related error message
    - Should indicate that authentication is required
   
    Args:
        ensureConda (fixture): Ensures Conda and anaconda-cli are properly installed
       
    Raises:
        AssertionError: If command succeeds when it should fail, or error message is missing
    """
    # Fail fast if `anaconda` isn't on PATH
    anaconda_path = shutil.which("anaconda")
    assert anaconda_path, "`anaconda` binary not in PATH — please install anaconda-cli"
   
    logger.info("Testing API key command when user is not logged in")
   
    # Step 1: Clear any existing authentication
    logout_command = f"{CLI_SUBCOMMAND} logout"
    capture(logout_command)  # Don't assert - it's OK if this fails when not logged in
    logger.info("Cleared any existing authentication")
   
    # Step 2: Run api-key command - should fail
    api_key_command = f"{CLI_SUBCOMMAND} api-key"
    output_bytes, exit_code = capture(api_key_command)
   
    # Step 3: Verify command failed appropriately
    assert exit_code != 0, (
        f"{api_key_command!r} should fail when user is not logged in, "
        f"but got exit code {exit_code}"
    )
   
    # Step 4: Verify error message contains login-related information
    output_text = output_bytes.decode().lower()
    login_keywords = ["login", "token", "auth", "required", "not found"]
   
    found_keyword = any(keyword in output_text for keyword in login_keywords)
    assert found_keyword, (
        f"Expected login-related error message containing one of {login_keywords}, "
        f"but got: {output_bytes.decode()}"
    )
   
    logger.info("Negative test case passed: Command correctly requires login")
    logger.info(f"Command executed: {api_key_command}")
    logger.info(f"Exit code received: {exit_code}")
    logger.info("Error message contains expected login-related keywords")