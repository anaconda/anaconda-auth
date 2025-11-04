# This test verifies that the Anaconda Auth package is installed and reports correct version.

import pytest
from src.common.cli_utils import capture
from src.common.defaults import (
    PACKAGE_NAME,
    CLI_SUBCOMMAND,
    ANACONDA_AUTH_VERSION,
    INSTALL_TIMEOUT,
    LIST_TIMEOUT,
    MAX_RETRIES,
)

@pytest.mark.integration
def test_verify_anaconda_auth_installed_and_version(ensureConda):
    """
    1) Check if `conda list PACKAGE_NAME` shows the package; if missing, install it.
    2) Assert `conda list PACKAGE_NAME` now succeeds.
    3) Run `CLI_SUBCOMMAND --version` and assert it contains ANACONDA_AUTH_VERSION.
    
    Args:
        ensureConda (fixture): Ensures Conda is properly installed
        
    Raises:
        AssertionError: If package installation fails or version check fails
    """
    # 1) Check if package is already installed
    out, code = capture(f"conda list {PACKAGE_NAME}", timeout=LIST_TIMEOUT)
    text = out.decode().lower()
    
    # Install package if not found
    package_missing = code != 0 or PACKAGE_NAME not in text
    if package_missing:
        success = False
        last_error = ""
        
        for attempt in range(1, MAX_RETRIES + 1):
            out_install, code_install = capture(
                f"conda install {PACKAGE_NAME} -y",
                timeout=INSTALL_TIMEOUT,
            )
            
            if code_install == 0:
                success = True
                break
            else:
                last_error = out_install.decode()
        
        assert success, f"Could not install {PACKAGE_NAME} after {MAX_RETRIES} attempts. Last error:\n{last_error}"
    
    # 2) Verify package is now listed
    out_verify, code_verify = capture(f"conda list {PACKAGE_NAME}", timeout=LIST_TIMEOUT)
    assert code_verify == 0, f"`conda list {PACKAGE_NAME}` failed: exit code {code_verify}"
    assert PACKAGE_NAME in out_verify.decode().lower(), f"Package {PACKAGE_NAME} not found in conda list output"
    
    # 3) Version check via CLI subcommand
    version_out, version_code = capture(f"{CLI_SUBCOMMAND} --version")
    assert version_code == 0, f"`{CLI_SUBCOMMAND} --version` failed with exit code {version_code}"
    
    version_text = version_out.decode().strip()
    assert ANACONDA_AUTH_VERSION in version_text, (
        f"Expected version '{ANACONDA_AUTH_VERSION}' in output of "
        f"`{CLI_SUBCOMMAND} --version`, but got:\n{version_text}"
    )