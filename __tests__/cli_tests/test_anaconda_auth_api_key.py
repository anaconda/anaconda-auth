# This test verifies the `anaconda auth api-key` command and get the API key after a full OAuth login flow(API + browser + CLI).

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
def test_auth_api_key_command(
    ensureConda,
    run_cli_command,
    api_request_context,
    credentials,
    urls,
    page,
    cli_runner
):

    logger.info("Running full login flow before API key check...")
    
    # Run full login flow with a clean HOME
    proc, port, clean_home = cli_runner()
    state = _perform_api_authentication(api_request_context, urls, credentials)
    _perform_browser_login(page, api_request_context, state, urls, credentials)
    _perform_cli_oauth_flow(lambda: (proc, port, clean_home), page)
    _verify_login_success(page, urls)
    
    # Use same HOME for api-key command to access saved login token
    logger.info("Calling: anaconda auth api-key")
    result = run_cli_command("anaconda auth api-key", extra_env={"HOME": clean_home})
    
    # Step 1: Assert CLI exited successfully
    assert result.returncode == 0, f"Command failed: {result.stderr or result.stdout}"
    
    output = result.stdout.strip()
    logger.info(f"CLI Output: {output}")
    
    # Step 2: Validate that a valid API key is present
    token_pattern = re.compile(r"[A-Za-z0-9\-_]{30,}")
    match = token_pattern.search(output)
    
    assert match, f"No valid API key found in CLI output: {output}"
    
    logger.info(f"Found valid API key: {match.group(0)}")