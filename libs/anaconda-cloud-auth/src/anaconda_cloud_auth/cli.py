import typer
from rich.prompt import Confirm

from anaconda_cli_base.console import console
from anaconda_cloud_auth import __version__
from anaconda_cloud_auth.actions import is_logged_in
from anaconda_cloud_auth.actions import login
from anaconda_cloud_auth.actions import logout
from anaconda_cloud_auth.client import BaseClient
from anaconda_cloud_auth.config import AuthConfig
from anaconda_cloud_auth.config import APIConfig
from anaconda_cloud_auth.token import TokenInfo
from anaconda_cloud_auth.token import TokenNotFoundError

app = typer.Typer(
    name="cloud", add_completion=False, help="Anaconda.cloud auth commands"
)


@app.callback(invoke_without_command=True)
def main(version: bool = typer.Option(False, "-V", "--version")) -> None:
    if version:
        console.print(
            f"Anaconda Cloud Auth, version [cyan]{__version__}[/cyan]",
            style="bold green",
        )
        raise typer.Exit()


@app.command("login")
def auth_login(force: bool = False, ssl_verify: bool = True) -> None:
    """Login"""
    try:
        auth_domain = AuthConfig().domain
        expired = TokenInfo.load(domain=auth_domain).expired
        if expired:
            console.print("Your API key has expired, logging into Anaconda.cloud")
            login(force=True, ssl_verify=ssl_verify)
            raise typer.Exit()
    except TokenNotFoundError:
        pass  # Proceed to login
    else:
        force = force or Confirm.ask(
            f"You are already logged into Anaconda Cloud ({auth_domain}). Would you like to force a new login?",
            default=False,
        )
        if not force:
            raise typer.Exit()

    login(force=force, ssl_verify=ssl_verify)


@app.command(name="whoami")
def auth_info() -> None:
    """Display information about the currently signed-in user"""
    api_config = APIConfig()

    if not (api_config.key or is_logged_in()):
        login()

    client = BaseClient()
    response = client.get("/api/account")
    console.print("Your Anaconda Cloud info:")
    console.print_json(data=response.json(), indent=2, sort_keys=True)


@app.command(name="api-key")
def auth_key() -> None:
    """Display API Key for signed-in user"""
    api_config = APIConfig()
    if api_config.key:
        console.print(api_config.key)
        return

    auth_config = AuthConfig()
    try:
        token_info = TokenInfo.load(domain=auth_config.domain)
        if not token_info.expired:
            console.print(token_info.api_key)
            return
    except TokenNotFoundError:
        pass

    login()
    token_info = TokenInfo.load(domain=auth_config.domain)
    console.print(token_info.api_key)


@app.command(name="logout")
def auth_logout() -> None:
    """Logout"""
    logout()
