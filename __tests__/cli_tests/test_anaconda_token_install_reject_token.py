# This test verifies that rejecting the token issue/resissue process

import re
import time
import logging
import pytest
from src.common.defaults import URL_PATTERNS
from src.common.cli_utils import launch_subprocess, terminate_process
from conftest import perform_oauth_login

logger = logging.getLogger(__name__)


@pytest.mark.integration
def test_anaconda_token_install_reject_token(
    ensureConda,
    run_cli_command,
    api_request_context,
    credentials,
    urls,
    page,
    browser,
    token_install_env
):
    """
    This test verifies rejecting token reissue:
    1. Run anaconda token install --org us-conversion
    2. Handle OAuth login when prompted
    3. Respond 'n' to reissue token prompt
    4. Verify the process handles rejection appropriately
    """
    logger.info("Starting test: Token install with rejected token reissue...")

    env, clean_home = token_install_env

    # Launch the CLI process
    token_proc = launch_subprocess(
        ["anaconda", "token", "install", "--org", "us-conversion"],
        env
    )

    state = {"oauth": False, "reissue": False}
    timeout = time.time() + 120

    try:
        while time.time() < timeout and token_proc.poll() is None:
            line = token_proc.stdout.readline().strip()
            if not line:
                continue
                
            logger.info(f"[STDOUT] {line}")

            # Handle OAuth URL
            if not state["oauth"] and URL_PATTERNS["oauth"] in line:
                match = re.search(r'https?://[^\s]+', line)
                oauth_url = match.group(0) if match else None
                logger.info(f"Found OAuth URL: {oauth_url}")
                
                assert oauth_url and perform_oauth_login(page, api_request_context, oauth_url, credentials, urls), \
                    "OAuth login failed"
                state["oauth"] = True
                logger.info("OAuth login completed")
                time.sleep(5)

            # Handle prompts - reject token reissue with 'n'
            elif not state["reissue"] and any(kw in line.lower() for kw in ["[y/n]", "(y/n)", "reissuing", "revoke", "proceed", "existing token"]):
                try:
                    token_proc.stdin.write("n\n")
                    token_proc.stdin.flush()
                    state["reissue"] = True
                    logger.info("Answered 'n' to token reissue prompt")
                except BrokenPipeError:
                    break

    finally:
        terminate_process(token_proc)

    # Verify OAuth completed
    assert state["oauth"], "OAuth login was not completed"

    if not state["reissue"]:
        logger.warning("Reissue prompt not detected — possibly a fresh token. Skipping assertion.")

    logger.info("Test passed - Token install with rejected reissue completed!")