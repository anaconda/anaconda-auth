"""
Interactive setup wizard for Anaconda authentication.

This module provides the `anaconda auth quickstart` command which helps users
configure their ~/.anaconda/config.toml file and optionally logs them in.
"""

import logging
import shutil
from pathlib import Path
from typing import Optional

import typer
from rich.panel import Panel
from rich.prompt import Confirm
from rich.prompt import Prompt

from anaconda_auth.actions import login
from anaconda_cli_base.config import anaconda_config_path
from anaconda_cli_base.console import console

log = logging.getLogger(__name__)

# Preset domains for easy selection
PRESET_DOMAINS = {
    "1": ("anaconda.com", "Cloud Package Security Manager"),
    "2": ("custom", "Custom/Private Instance"),
}


def get_backup_path(config_path: Path) -> Path:
    """Get the backup file path for the config file."""
    return config_path.with_suffix(".toml.backup")


def backup_config(config_path: Path) -> Optional[Path]:
    """Backup existing config file if it exists.

    Args:
        config_path: Path to the config file to backup

    Returns:
        Path to backup file if created, None otherwise
    """
    if config_path.exists():
        backup_path = get_backup_path(config_path)
        shutil.copy(config_path, backup_path)
        console.print(f"[green]Backup created: {backup_path}[/green]")
        return backup_path
    return None


def restore_config(config_path: Path) -> bool:
    """Restore config from backup file.

    Args:
        config_path: Path to the config file to restore

    Returns:
        True if restore was successful, False otherwise
    """
    backup_path = get_backup_path(config_path)
    if backup_path.exists():
        shutil.copy(backup_path, config_path)
        console.print(f"[green]Restored configuration from: {backup_path}[/green]")
        return True
    else:
        console.print("[yellow]No backup file found. Nothing to restore.[/yellow]")
        return False


def select_domain_interactive() -> str:
    """Prompt user to select a domain interactively.

    Returns:
        The selected domain string
    """
    console.print("\n[bold]Which Anaconda service do you want to use?[/bold]\n")

    for key, (domain, description) in PRESET_DOMAINS.items():
        if domain != "custom":
            console.print(f"  {key}. {description} ([cyan]{domain}[/cyan])")
        else:
            console.print(f"  {key}. {description}")

    selection = Prompt.ask(
        "\nSelection",
        choices=list(PRESET_DOMAINS.keys()),
        default="1",
    )

    domain, _ = PRESET_DOMAINS[selection]

    if domain == "custom":
        domain = Prompt.ask(
            "Enter your domain (e.g., my-company.anaconda.com)",
        )
        # Strip any protocol prefix if user included it
        domain = domain.replace("https://", "").replace("http://", "").strip("/")

    return domain


def write_config(config_path: Path, domain: str) -> None:
    """Write the configuration file with the specified domain.

    Args:
        config_path: Path to write the config file
        domain: The domain to configure
    """
    # Ensure parent directory exists
    config_path.parent.mkdir(parents=True, exist_ok=True)

    # Write TOML configuration
    config_content = f'''[plugin.auth]
domain = "{domain}"
'''
    config_path.write_text(config_content)


def run_login() -> bool:
    """Run the anaconda auth login action.

    Returns:
        True if login was successful, False otherwise
    """
    console.print("\n[bold]Opening browser for authentication...[/bold]")
    try:
        login()
        return True
    except Exception as e:
        log.debug(f"Login failed: {e}")
        return False


def quickstart(
    restore: bool = typer.Option(
        False,
        "--restore",
        help="Restore configuration from backup",
    ),
) -> None:
    """
    Interactive setup wizard for Anaconda authentication.

    Configures ~/.anaconda/config.toml with your Anaconda domain
    and optionally logs you in.

    Examples:

        # Interactive setup
        anaconda auth quickstart

        # Restore previous configuration
        anaconda auth quickstart --restore
    """
    config_path = anaconda_config_path()

    # Handle restore
    if restore:
        restore_config(config_path)
        return

    # Show header
    console.print(
        Panel.fit(
            "[bold]Anaconda Authentication Setup[/bold]\n\n"
            "This wizard will configure authentication for Anaconda services.\n"
            f"Config file: [cyan]{config_path}[/cyan]",
            border_style="blue",
        )
    )

    # Check for existing config
    if config_path.exists():
        console.print(
            f"\n[yellow]Existing configuration found at {config_path}[/yellow]"
        )

    # Interactive domain selection
    selected_domain = select_domain_interactive()

    # Show what will be configured
    console.print(
        f"\n[green]Will configure domain:[/green] [bold]{selected_domain}[/bold]"
    )

    # Confirm with user
    if not Confirm.ask(
        "\n[bold]Apply this configuration?[/bold]\n(Existing config will be backed up)",
        default=True,
    ):
        console.print("[yellow]Setup cancelled.[/yellow]")
        raise typer.Abort()

    # Backup existing config
    backup_config(config_path)

    # Write new configuration
    write_config(config_path, selected_domain)
    console.print(f"\n[bold green]Configuration saved to {config_path}[/bold green]")

    # Ask if user wants to login
    should_login = Confirm.ask(
        "\n[bold]Would you like to login now?[/bold]",
        default=True,
    )

    if should_login:
        success = run_login()
        if success:
            console.print(
                "\n[bold green]Setup complete! "
                "You're ready to use Anaconda services.[/bold green]"
            )
        else:
            console.print(
                "\n[yellow]Configuration saved, but login was not completed. "
                "Run 'anaconda auth login' when ready.[/yellow]"
            )
    else:
        console.print(
            "\n[green]Setup complete! "
            "Run 'anaconda auth login' when you're ready to authenticate.[/green]"
        )
