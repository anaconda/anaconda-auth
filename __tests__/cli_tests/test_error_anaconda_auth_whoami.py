# This test verifies the `anaconda auth whoami` command shows proper error when user is not logged in (clean environment with no auth token).

import logging
import pytest

logger = logging.getLogger(__name__)


@pytest.mark.integration
def test_auth_whoami_not_logged_in(
    ensureConda,
    run_cli_command,
    tmp_path
):

    logger.info("Testing whoami command without login...")
    
    # Create a clean HOME directory to ensure no cached credentials
    clean_home = tmp_path / "clean_home"
    clean_home.mkdir()
    
    # Run whoami command with clean HOME (no auth token)
    logger.info("Calling: anaconda auth whoami (without login)")
    result = run_cli_command(
        "anaconda auth whoami", 
        extra_env={"HOME": str(clean_home)}
    )
    
    # Step 1: Assert CLI exits with error (non-zero return code)
    assert result.returncode != 0, f"Expected command to fail, but it succeeded with output: {result.stdout}"
    
    # Step 2: Verify error message mentions authentication/login required
    error_output = (result.stderr or result.stdout).strip()
    logger.info(f"CLI Error Output: {error_output}")
    
    # Check for common error patterns
    error_keywords = ["login", "required", "authenticated", "authenticationmissingerror", "not logged in"]
    assert any(keyword in error_output.lower() for keyword in error_keywords), \
        f"Expected authentication error message, but got: {error_output}"
    
    logger.info("Correctly showed error for unauthenticated whoami command")