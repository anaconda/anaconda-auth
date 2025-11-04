# This test verifies the package search functionality in conda, ensuring it uses the expected channel.

import os
import logging
from pathlib import Path
import pytest
from src.common.cli_utils import capture
from src.common.defaults import (
    DEFAULT_CHANNEL,
    EXPECTED_CHANNEL,
    SEARCH_PACKAGE,
    SEARCH_HEADER_PREFIX
)

logger = logging.getLogger(__name__)


@pytest.mark.integration
def test_conda_config_and_search(isolated_conda_env, caplog, ensureConda):
    """Test conda configuration and package search functionality."""
    caplog.set_level("INFO")

    # Step 1: Ensure default channel only
    ensure_default_channel_only()

    # Step 2: Search and verify channel
    verify_package_search_channel()


def ensure_default_channel_only():
    """Ensure only default channel is configured."""
    out, code = capture("conda config --show channels")
    assert code == 0, f"Failed to get conda channels configuration: {out.decode()}"
    
    channels = out.decode().strip().split('\n')
    if len(channels) == 1 and channels[0] == f"- {DEFAULT_CHANNEL}":
        return
    
    # Reset to default channel only
    capture("conda config --remove-key channels")
    out, rc = capture(f"conda config --add channels {DEFAULT_CHANNEL}")
    assert rc == 0, f"Failed to add default channel '{DEFAULT_CHANNEL}': {out.decode()}"


def verify_package_search_channel():
    """Search for package and verify it uses expected channel."""
    out, code = capture(f"conda search {SEARCH_PACKAGE}")
    assert code == 0, f"Failed to search for package '{SEARCH_PACKAGE}': {out.decode()}"

    lines = out.decode().splitlines()
    
    # Find header line
    header_idx = next((i for i, line in enumerate(lines) 
                      if line.lower().startswith(SEARCH_HEADER_PREFIX)), -1)
    
    if header_idx == -1:
        pytest.skip(f"No search results found for '{SEARCH_PACKAGE}'")

    # Check all packages are from expected channel
    packages_found = False
    for line in lines[header_idx + 1:]:
        if line.strip():
            packages_found = True
            channel = line.split()[-1]
            assert channel == EXPECTED_CHANNEL, \
                f"Package found in unexpected channel '{channel}', expected '{EXPECTED_CHANNEL}'"
    
    assert packages_found, "No packages found after header line"