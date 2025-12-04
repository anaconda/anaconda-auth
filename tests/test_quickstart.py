"""Tests for the anaconda auth quickstart command."""

from pathlib import Path
from unittest.mock import patch

import pytest

from .conftest import CLIInvoker


def test_quickstart(
    invoke_cli: CLIInvoker, tmp_cwd: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test that quickstart creates config file interactively."""
    config_path = tmp_cwd / ".anaconda" / "config.toml"
    monkeypatch.setattr(
        "anaconda_auth.quickstart.anaconda_config_path",
        lambda: config_path,
    )

    # Mock configured sites and user selection
    with patch(
        "anaconda_auth.quickstart.get_configured_sites",
        return_value=[],  # No configured sites
    ), patch(
        "anaconda_auth.quickstart.Prompt.ask",
        return_value="1",  # Select anaconda.com (first option)
    ), patch(
        "anaconda_auth.quickstart.Confirm.ask", side_effect=[True, False]
    ):  # Apply config, skip login
        result = invoke_cli(["auth", "quickstart"])

    assert result.exit_code == 0
    assert config_path.exists()

    content = config_path.read_text()
    assert 'domain = "anaconda.com"' in content
    assert "[plugin.auth]" in content


def test_quickstart_restore(
    invoke_cli: CLIInvoker, tmp_cwd: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test that quickstart --restore works."""
    config_dir = tmp_cwd / ".anaconda"
    config_dir.mkdir(parents=True)
    config_path = config_dir / "config.toml"
    backup_path = config_dir / "config.toml.backup"

    # Create backup file
    backup_content = '[plugin.auth]\ndomain = "backup.domain.com"\n'
    backup_path.write_text(backup_content)

    # Create current config with different content
    config_path.write_text('[plugin.auth]\ndomain = "current.domain.com"\n')

    monkeypatch.setattr(
        "anaconda_auth.quickstart.anaconda_config_path",
        lambda: config_path,
    )

    # Run restore
    result = invoke_cli(["auth", "quickstart", "--restore"])

    assert result.exit_code == 0
    assert config_path.read_text() == backup_content
