# This test verifies the miniconda installation and the `conda info` command including conda version check.

import re
import pytest
from src.common.cli_utils import capture
from src.common.defaults import CONDA_VERSION

@pytest.mark.integration
def test_conda_info_command_runs_successfully(ensureConda):
    """
    Ensure `conda info` command runs without errors.
    """
    # Run `conda info`
    out_bytes, exit_code = capture("conda info")
    assert exit_code == 0, f"`conda info` failed: exit code {exit_code}"

@pytest.mark.integration
def test_conda_info_reports_correct_version(ensureConda):
    """
    Ensure `conda info` prints the expected conda version.
    """
    # Run `conda info`
    out_bytes, exit_code = capture("conda info")
    assert exit_code == 0, f"`conda info` failed: exit code {exit_code}"
    output = out_bytes.decode()
   
    # Locate and validate the version line
    version_found = False
    for line in output.splitlines():
        stripped = line.strip()  # remove leading/trailing spaces
        if stripped.lower().startswith("conda version"):
            # After the colon, expect the specific version from defaults
            version_part = stripped.split(":", 1)[1].strip()
            assert version_part == CONDA_VERSION, (
                f"Expected conda version '{CONDA_VERSION}', got '{version_part}'"
            )
            version_found = True
            break
    
    assert version_found, "Did not find any line starting with 'conda version'"

@pytest.mark.integration
def test_conda_info_shows_active_environment_section(ensureConda):
    """
    Ensure `conda info` includes the active environment section.
    """
    # Run `conda info`
    out_bytes, exit_code = capture("conda info")
    assert exit_code == 0, f"`conda info` failed: exit code {exit_code}"
    output = out_bytes.decode()
   
    # Check for the active environment section
    assert "active environment" in output.lower(), (
        "Output is missing an 'active environment' section"
    )