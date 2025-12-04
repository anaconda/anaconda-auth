"""
Interactive setup wizard for Anaconda authentication.

This module provides the `anaconda auth quickstart` command which helps users
configure their ~/.anaconda/config.toml file and optionally logs them in.
"""

import logging
import shutil
from pathlib import Path
from typing import List, Optional, Tuple

import typer
from rich.panel import Panel
from rich.prompt import Confirm
from rich.prompt import Prompt

from anaconda_auth.actions import login
from anaconda_auth.config import AnacondaAuthSitesConfig
from anaconda_cli_base.config import anaconda_config_path
from anaconda_cli_base.console import console

log = logging.getLogger(__name__)


def get_configured_sites() -> List[Tuple[str, str]]:
    """Get list of configured sites from config.toml.

    Returns:
        List of tuples (site_key, domain) for configured sites
    """
    try:
        sites_config = AnacondaAuthSitesConfig()
        configured_sites = []
        for site_key in sites_config.sites.root.keys():
            site = sites_config.sites.root[site_key]
            configured_sites.append((site_key, site.domain))
        return configured_sites
    except Exception as e:
        log.debug(f"Failed to load configured sites: {e}")
        return []


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

    # Get configured sites from config.toml
    configured_sites = get_configured_sites()

    # Build list of available sites
    # Start with anaconda.com if not already in configured sites
    site_options: List[Tuple[str, str]] = []
    anaconda_com_exists = any(domain == "anaconda.com" for _, domain in configured_sites)

    if not anaconda_com_exists:
        site_options.append(("anaconda.com", "anaconda.com"))

    # Add all configured sites
    site_options.extend(configured_sites)

    # Display options
    for idx, (site_key, domain) in enumerate(site_options, start=1):
        if site_key == domain:
            # Simple site, just show domain
            console.print(f"  {idx}. {domain}")
        else:
            # Named site, show both name and domain
            console.print(f"  {idx}. {site_key} ([cyan]{domain}[/cyan])")

    # Add "custom domain" option at the end
    custom_option_idx = len(site_options) + 1
    console.print(f"  {custom_option_idx}. Custom domain")

    # Get valid choices as strings
    valid_choices = [str(i) for i in range(1, custom_option_idx + 1)]

    selection = Prompt.ask(
        "\nSelection",
        choices=valid_choices,
        default="1",
    )

    selected_idx = int(selection)

    # Check if user selected custom domain
    if selected_idx == custom_option_idx:
        domain = Prompt.ask(
            "Enter your domain (e.g., my-company.anaconda.com)",
        )
        # Strip any protocol prefix if user included it
        domain = domain.replace("https://", "").replace("http://", "").strip("/")
    else:
        # User selected an existing site
        _, domain = site_options[selected_idx - 1]

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
