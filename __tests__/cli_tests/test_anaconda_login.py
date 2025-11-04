# This test verifies the anaconda auth login flow using API, browser, and CLI and verfies the success message after login.

import re
import time
import logging
import subprocess
import pytest
from subprocess import TimeoutExpired
from playwright.sync_api import Page, Browser, expect

from src.common.defaults import (
    URL_PATTERNS,
    EXPECTED_TEXT,
    PAGE_LOAD_TIMEOUT,
    NETWORK_IDLE_TIMEOUT,
    OAUTH_CAPTURE_TIMEOUT,
    CLI_COMPLETION_TIME,
)

logger = logging.getLogger(__name__)

@pytest.mark.parametrize("auth_method", ["api", "browser", "cli_oauth", "full_flow"], 
                         ids=["API-Only", "Browser-Only", "CLI-Only", "Full-Integration"])
@pytest.mark.usefixtures("ensureConda")
def test_anaconda_login_flow(
    auth_method, api_request_context, credentials, urls, 
    request  # Used to conditionally get fixtures
):
    """Test Anaconda login flow components individually or as complete integration.
    
    Args:
        auth_method: The authentication method to test
    """
    
    if auth_method == "api":
        # API only - no browser needed
        state = _perform_api_authentication(api_request_context, urls, credentials)
        assert state is not None, "API authentication should return a valid state"
        
    elif auth_method == "browser":
        # Browser needed - get page fixture
        page = request.getfixturevalue("page")
        state = _perform_api_authentication(api_request_context, urls, credentials)
        _perform_browser_login(page, api_request_context, state, urls, credentials)
        assert page.url.startswith(urls['ui']), f"Expected to be on {urls['ui']}, got {page.url}"
        
    elif auth_method == "cli_oauth":
        # Browser and CLI needed
        page = request.getfixturevalue("page")
        cli_runner = request.getfixturevalue("cli_runner")
        oauth_url = _perform_cli_oauth_flow(cli_runner, page)
        assert oauth_url and URL_PATTERNS["oauth"] in oauth_url, "CLI OAuth should return valid URL"
        
    elif auth_method == "full_flow":
        # Complete end-to-end integration - all fixtures needed
        page = request.getfixturevalue("page")
        cli_runner = request.getfixturevalue("cli_runner")
        
        state = _perform_api_authentication(api_request_context, urls, credentials)
        _perform_browser_login(page, api_request_context, state, urls, credentials)
        oauth_url = _perform_cli_oauth_flow(cli_runner, page)
        _verify_login_success(page, urls)
        logger.info("Complete end‐to‐end CLI+browser login flow completed successfully!")


def _perform_api_authentication(api_request_context, urls, credentials):
    """Step 1: Perform API authentication and return state."""
    logger.info("Step 1: Performing API authentication...")
    
    auth = api_request_context.post(f"/api/auth/authorize?return_to={urls['ui']}")
    assert auth.ok, f"Authorize failed: {auth.status}"
    
    state = auth.json().get("state")
    assert state, "No state returned from authorize"
    
    login = api_request_context.post(f"/api/auth/login/password/{state}", data=credentials)
    assert login.ok, f"Password login failed: {login.status}"
    
    logger.info("Step 1: API authentication completed.")
    return state


def _perform_browser_login(page, api_request_context, state, urls, credentials):
    """Step 2: Complete browser login using API state."""
    logger.info("Step 2: Performing browser login...")
    
    login = api_request_context.post(f"/api/auth/login/password/{state}", data=credentials)
    redirect_url = login.json().get("redirect")
    assert redirect_url, "No redirect URL returned"
    
    page.goto(redirect_url, timeout=PAGE_LOAD_TIMEOUT)
    expect(page.get_by_text(EXPECTED_TEXT["welcome"])).to_be_visible(timeout=PAGE_LOAD_TIMEOUT)
    
    assert page.url.startswith(urls['ui']), f"Expected to be on {urls['ui']}, got {page.url}"
    logger.info("Step 2: Browser login completed (Welcome Back shown).")


def _perform_cli_oauth_flow(cli_runner, page):
    """Step 3: Start CLI process and complete OAuth flow."""
    logger.info("Step 3: Starting CLI OAuth flow...")
    
    proc, port, clean_home = cli_runner()
    logger.info(f"CLI process PID: {proc.pid}, listening on port {port}")
    
    oauth_url = _capture_oauth_url_from_cli(proc)
    assert oauth_url, "Failed to capture OAuth URL from CLI"
    
    logger.info("Navigating to OAuth URL in browser...")
    page.goto(oauth_url, timeout=PAGE_LOAD_TIMEOUT)
    page.wait_for_load_state("networkidle", timeout=NETWORK_IDLE_TIMEOUT)
    
    _wait_for_cli_completion(proc)
    logger.info("Step 3: CLI OAuth flow completed.")
    return oauth_url


def _capture_oauth_url_from_cli(proc):
    """Capture OAuth URL from CLI stdout."""
    oauth_url, start_time = None, time.time()
    
    while time.time() - start_time < OAUTH_CAPTURE_TIMEOUT:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                break
            time.sleep(0.05)
            continue
        
        line = line.strip()
        logger.debug(f"[CLI stdout] {line}")
        
        matches = re.findall(r"https?://[^\s]+", line)
        for u in matches:
            if URL_PATTERNS["oauth"] in u:
                oauth_url = u
                logger.info(f"Captured OAuth URL: {oauth_url}")
                break
        if oauth_url:
            break
    return oauth_url


def _wait_for_cli_completion(proc):
    """Wait for CLI process to exit gracefully."""
    logger.info("Waiting for CLI to exit...")
    start_time, cli_exited = time.time(), False
    
    while time.time() - start_time < CLI_COMPLETION_TIME:
        if proc.poll() is not None:
            cli_exited = True
            logger.info(f"CLI exited with code {proc.returncode}")
            break
        time.sleep(0.1)  # Slightly longer sleep to reduce CPU usage
    
    if not cli_exited:
        logger.info("CLI didn't exit naturally, attempting graceful termination...")
        try:
            # Try graceful termination first
            proc.terminate()
            proc.wait(timeout=3)
            logger.info("CLI terminated gracefully")
        except subprocess.TimeoutExpired:
            # Force kill if graceful termination fails
            logger.warning("CLI didn't respond to termination, force killing...")
            proc.kill()
            proc.wait(timeout=2)
            logger.warning("CLI force killed")


def _verify_login_success(page, urls):
    """Step 4: Verify successful login on success page."""
    logger.info("Step 4: Verifying login success...")
    
    success_url = f"{urls['ui']}{URL_PATTERNS['success']}"
    page.goto(success_url, timeout=PAGE_LOAD_TIMEOUT)
    page.wait_for_load_state("networkidle", timeout=NETWORK_IDLE_TIMEOUT)
    
    assert URL_PATTERNS["success"] in page.url, f"Expected '{URL_PATTERNS['success']}' in URL, got {page.url}"
    expect(page.get_by_text(EXPECTED_TEXT["success"])).to_be_visible(timeout=PAGE_LOAD_TIMEOUT)
    
    page.context.close()
    logger.info("Step 4: Success verification completed.")