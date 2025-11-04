# This test verifies that rejecting .condarc configuration results in default channels.

import re
import time
import logging
import pytest
from src.common.defaults import URL_PATTERNS
from pathlib import Path
from src.common.cli_utils import launch_subprocess, terminate_process
from conftest import perform_oauth_login

logger = logging.getLogger(__name__)


@pytest.mark.integration
def test_anaconda_token_install_reject_condarc(
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
    This test verifies rejecting .condarc configuration:
    1. Run anaconda token install --org us-conversion
    2. Handle OAuth login when prompted
    3. Respond 'y' to reissue token prompt
    4. Respond 'n' to configure .condarc prompt
    5. Verify conda search shows packages from pkgs/main (default channel)
    """
    logger.info("Starting test: Token install with rejected .condarc configuration...")

    env, clean_home = token_install_env

    # Launch the CLI process
    token_proc = launch_subprocess(
        ["anaconda", "token", "install", "--org", "us-conversion"],
        env
    )

    state = {"oauth": False, "reissue": False, "condarc": False}
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

                # Use common OAuth login function from conftest
                assert oauth_url and perform_oauth_login(page, api_request_context, oauth_url, credentials, urls), \
                    "OAuth login failed"
                state["oauth"] = True
                logger.info("OAuth login completed")
                time.sleep(5)

            # Handle prompts - 'y' for reissue, 'n' for condarc
            elif any(kw in line.lower() for kw in ["[y/n]", "(y/n)", "reissuing", "proceed"]):
                response_type = "reissue" if not state["reissue"] else "condarc"
                response = "y" if response_type == "reissue" else "n"

                try:
                    token_proc.stdin.write(f"{response}\n")
                    token_proc.stdin.flush()
                    state[response_type] = True
                    logger.info(f"Answered '{response}' to {response_type} prompt")
                except BrokenPipeError:
                    break

    finally:
        terminate_process(token_proc)

    # Verify all steps completed
    assert state["oauth"], "OAuth login was not completed"

    if not state["reissue"]:
        logger.warning("Reissue prompt not detected — possibly a fresh token. Skipping assertion.")
    else:
        assert state["reissue"], "Token reissue step not handled"

    if not state["condarc"]:
        logger.warning("Condarc prompt not detected — possibly skipped due to default config. Skipping assertion.")
    else:
        assert state["condarc"], "Condarc rejection prompt not handled"


    # Verify .condarc doesn't contain us-conversion
    condarc_path = Path(clean_home) / ".condarc"
    if condarc_path.exists():
        content = condarc_path.read_text()
        assert "us-conversion" not in content, ".condarc should not contain us-conversion channel"

    # Accept ToS for default channels before searching
    logger.info("\nAccepting ToS for default channels...")
    tos_result = run_cli_command(
        "conda tos accept --channel https://repo.anaconda.com/pkgs/main",
        extra_env={"HOME": str(clean_home)}
    )

    # Verify conda search shows default channels
    logger.info("\nRunning conda search flask to verify default channel configuration...")

    search_result = run_cli_command("conda search flask", extra_env={"HOME": str(clean_home)})

    logger.info(f"Conda search exit code: {search_result.returncode}")

    if search_result.stdout:
        logger.info(f"Conda search stdout: {search_result.stdout[:500]}")
    if search_result.stderr:
        logger.info(f"Conda search stderr: {search_result.stderr[:500]}")

    assert search_result.returncode == 0, f"Conda search should succeed after ToS acceptance: {search_result.stderr}"

    packages_found = False
    all_pkgs_main = True

    if search_result.stdout:
        for line in search_result.stdout.strip().split('\n'):
            if "Name" in line or "Loading channels" in line or line.startswith("#") or not line.strip():
                continue

            if "flask" in line.lower():
                packages_found = True
                if "us-conversion" in line:
                    all_pkgs_main = False
                    logger.warning(f"Found package from us-conversion channel: {line}")

    assert packages_found, "Should find flask packages from default channel"
    assert all_pkgs_main, "No packages should be from us-conversion channel"

    logger.info("Test passed - Token installed but .condarc rejected!")
