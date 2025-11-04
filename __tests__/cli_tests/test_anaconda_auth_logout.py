# This test verifies the `anaconda auth logout` command successfully logs out user and clears authentication tokens.
 
import logging
import pytest
from .test_anaconda_login import (
    _perform_api_authentication,
    _perform_browser_login,
    _perform_cli_oauth_flow,
    _verify_login_success
)
 
logger = logging.getLogger(__name__)
 
 
@pytest.mark.integration
def test_auth_logout_command(
    ensureConda,
    run_cli_command,
    api_request_context,
    credentials,
    urls,
    page,
    cli_runner
):
    """Test that `anaconda auth logout` successfully logs out an authenticated user."""
    logger.info("Testing anaconda auth logout...")
    # Login
    proc, port, clean_home = cli_runner()
    state = _perform_api_authentication(api_request_context, urls, credentials)
    _perform_browser_login(page, api_request_context, state, urls, credentials)
    _perform_cli_oauth_flow(lambda: (proc, port, clean_home), page)
    _verify_login_success(page, urls)
    # Logout
    logger.info("Calling: anaconda auth logout")
    logout_result = run_cli_command("anaconda auth logout", extra_env={"HOME": clean_home})
    assert logout_result.returncode == 0, "Logout command should succeed"
    # Verify logged out using whoami
    whoami_result = run_cli_command("anaconda auth whoami", extra_env={"HOME": clean_home})
    assert whoami_result.returncode != 0, "whoami should fail after logout"
    logger.info("Logout test passed - user successfully logged out")
 
 
@pytest.mark.integration
def test_auth_logout_when_not_logged_in(ensureConda, run_cli_command, tmp_path):
    """Test that logout succeeds even when not logged in (idempotent)."""
    clean_home = tmp_path / "clean_home"
    clean_home.mkdir()
    # Run logout without being logged in
    logout_result = run_cli_command("anaconda auth logout", extra_env={"HOME": str(clean_home)})
    assert logout_result.returncode == 0, "Logout should succeed even when not logged in"
    logger.info("Logout idempotency test passed")