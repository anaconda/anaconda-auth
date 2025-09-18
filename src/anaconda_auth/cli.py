import sys
import warnings
from textwrap import dedent
from typing import Optional

import typer
from requests.exceptions import HTTPError
from requests.exceptions import JSONDecodeError
from rich.prompt import Confirm
from rich.syntax import Syntax

from anaconda_auth import __version__
from anaconda_auth.actions import login
from anaconda_auth.actions import logout
from anaconda_auth.client import BaseClient
from anaconda_auth.config import AnacondaAuthConfig
from anaconda_auth.exceptions import TokenExpiredError
from anaconda_auth.token import TokenInfo
from anaconda_auth.token import TokenNotFoundError
from anaconda_cli_base.config import anaconda_config_path
from anaconda_cli_base.console import console
from anaconda_cli_base.exceptions import register_error_handler


def _continue_with_login() -> int:
    if sys.stdout.isatty():
        do_login = Confirm.ask("Continue with interactive login?", choices=["y", "n"])
        if do_login:
            login()
            return -1
        else:
            console.print(
                dedent("""
                To configure your credentials you can run
                  [green]anaconda login --at anaconda.com[/green]

                or set your API key using the [green]ANACONDA_AUTH_API_KEY[/green] env var

                or set
                """)
            )
            console.print(
                Syntax(
                    dedent(
                        """\
                        [plugin.auth]
                        api_key = "<api-key>"
                        """
                    ),
                    "toml",
                    background_color=None,
                )
            )
            console.print(f"in {anaconda_config_path()}")
    return 1


def _login_required_message(error_classifier: str) -> None:
    console.print(
        f"[bold][red]{error_classifier}[/red][/bold]: Login is required to complete this action."
    )


@register_error_handler(TokenNotFoundError)
def login_required(e: Exception) -> int:
    _login_required_message(e.__class__.__name__)
    return _continue_with_login()


@register_error_handler(TokenExpiredError)
def token_expired(e: Exception) -> int:
    console.print(
        f"[bold][red]{e.__class__.__name__}[/red][/bold]: Your login token has expired"
    )

    return _continue_with_login()


@register_error_handler(HTTPError)
def http_error(e: HTTPError) -> int:
    try:
        error_code = e.response.json().get("error", {}).get("code", "")
    except JSONDecodeError:
        error_code = ""

    if error_code == "auth_required":
        if "Authorization" in e.request.headers:
            console.print(
                "[bold][red]InvalidAuthentication:[/red][/bold] Your provided API Key or login token is invalid"
            )
        else:
            _login_required_message("AuthenticationMissingError")
        return _continue_with_login()
    else:
        console.print(f"[bold][red]{e.__class__.__name__}:[/red][/bold] {e}")
        return 1


app = typer.Typer(name="auth", add_completion=False, help="anaconda.com auth commands")


@app.callback(invoke_without_command=True)
def main(
    version: bool = typer.Option(False, "-V", "--version"),
    name: Optional[str] = typer.Option(
        None,
        "-n",
        "--name",
        hidden=True,
    ),
    organization: Optional[str] = typer.Option(
        None,
        "-o",
        "--org",
        "--organization",
        hidden=True,
    ),
    strength: Optional[str] = typer.Option(
        None,
        "--strength",
        hidden=True,
    ),
    strong: Optional[bool] = typer.Option(
        None,
        "--strong",
        hidden=True,
    ),
    weak: Optional[bool] = typer.Option(
        None,
        "-w",
        "--weak",
        hidden=True,
    ),
    url: Optional[str] = typer.Option(
        None,
        "--url",
        hidden=True,
    ),
    max_age: Optional[str] = typer.Option(
        None,
        "--max-age",
        hidden=True,
    ),
    scopes: Optional[str] = typer.Option(
        None,
        "-s",
        "--scopes",
        hidden=True,
    ),
    out: Optional[str] = typer.Option(
        None,
        "--out",
        hidden=True,
    ),
    list_scopes: Optional[bool] = typer.Option(
        None,
        "-x",
        "--list-scopes",
        hidden=True,
    ),
    list_tokens: Optional[bool] = typer.Option(
        None,
        "-l",
        "--list",
        hidden=True,
    ),
    remove: Optional[str] = typer.Option(
        None,
        "-r",
        "--remove",
        hidden=True,
    ),
    create: Optional[bool] = typer.Option(
        None,
        "-c",
        "--create",
        hidden=True,
    ),
    info: Optional[bool] = typer.Option(
        None,
        "-i",
        "--info",
        "--current-info",
        hidden=True,
    ),
) -> None:
    if version:
        console.print(
            f"anaconda-auth, version [cyan]{__version__}[/cyan]",
            style="bold green",
        )
        raise typer.Exit()

    has_options = any(
        value is not None
        for value in (
            name,
            organization,
            strength,
            strong,
            weak,
            url,
            max_age,
            scopes,
            out,
            list_scopes,
            list_tokens,
            remove,
            create,
            info,
        )
    )
    if has_options:
        # If any of the anaconda-client options are passed, try to delegate to
        # binstar_main if it exists. Otherwise, we just exit gracefully.

        try:
            from binstar_client.scripts.cli import main as binstar_main
        except (ImportError, ModuleNotFoundError):
            return

        console.print(
            "[yellow]DeprecationWarning[/yellow]: Please use [cyan]anaconda org auth[/cyan] instead for explicit management of anaconda.org auth tokens\n"
        )
        warnings.warn(
            "Please use `anaconda org auth` instead for explicit management of anaconda.org auth tokens",
            DeprecationWarning,
        )

        binstar_main(sys.argv[1:], allow_plugin_main=False)


@app.command("login")
def auth_login(force: bool = False, ssl_verify: bool = True) -> None:
    """Login"""
    try:
        auth_domain = AnacondaAuthConfig().domain
        expired = TokenInfo.load(domain=auth_domain).expired
        if expired:
            console.print("Your API key has expired, logging into anaconda.com")
            login(force=True, ssl_verify=ssl_verify)
            raise typer.Exit()
    except TokenNotFoundError:
        pass  # Proceed to login
    else:
        force = force or Confirm.ask(
            f"You are already logged into Anaconda ({auth_domain}). Would you like to force a new login?",
            default=False,
        )
        if not force:
            raise typer.Exit()

    login(force=force, ssl_verify=ssl_verify)


@app.command(name="whoami")
def auth_info() -> None:
    """Display information about the currently signed-in user"""
    client = BaseClient()
    response = client.get("/api/account")
    response.raise_for_status()
    console.print("Your anaconda.com info:")
    console.print_json(data=response.json(), indent=2, sort_keys=True)


@app.command(name="api-key")
def auth_key() -> None:
    """Display API Key for signed-in user"""
    config = AnacondaAuthConfig()
    if config.api_key:
        print(config.api_key)
        return

    token_info = TokenInfo.load(domain=config.domain)
    if not token_info.expired:
        print(token_info.api_key)
        return
    else:
        raise TokenExpiredError()


@app.command(name="logout")
def auth_logout() -> None:
    """Logout"""
    logout()
