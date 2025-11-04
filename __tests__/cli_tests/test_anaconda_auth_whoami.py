# This test verifies the `anaconda auth whoami` command shows logged-in user details after OAuth login.

import re
import logging
import pytest
from playwright.sync_api import Page
from .test_anaconda_login import (
    _perform_api_authentication,
    _perform_browser_login,
    _perform_cli_oauth_flow,
    _verify_login_success
)

logger = logging.getLogger(__name__)


@pytest.mark.integration
def test_auth_whoami_command(
    ensureConda,
    run_cli_command,
    api_request_context,
    credentials,
    urls,
    page,
    cli_runner
):

    logger.info("Running full login flow before whoami check...")
    
    # Run full login flow with a clean HOME
    proc, port, clean_home = cli_runner()
    state = _perform_api_authentication(api_request_context, urls, credentials)
    _perform_browser_login(page, api_request_context, state, urls, credentials)
    _perform_cli_oauth_flow(lambda: (proc, port, clean_home), page)
    _verify_login_success(page, urls)
    
    # Use same HOME for whoami command to access saved login token
    logger.info("Calling: anaconda auth whoami")
    result = run_cli_command("anaconda auth whoami", extra_env={"HOME": clean_home})
    
    # Step 1: Assert CLI exited successfully
    assert result.returncode == 0, f"Command failed: {result.stderr or result.stdout}"
    
    output = result.stdout.strip()
    logger.info(f"CLI Output: {output}")
    
    # Step 2: Validate that user info is present
    # Check for email from credentials in the output
    expected_email = credentials["email"]
    assert expected_email in output, f"Expected email '{expected_email}' not found in output: {output}"
    
    # Step 3: Validate output contains typical whoami fields (username, email, etc.)
    # Common fields that might appear: username, email, name, id
    assert any(field in output.lower() for field in ["username", "email", "user", "name"]), \
        f"No user information fields found in output: {output}"
    
    logger.info(f"Found user details for: {expected_email}")