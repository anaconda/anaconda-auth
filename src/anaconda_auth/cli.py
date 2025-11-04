import sys
import warnings
from textwrap import dedent
from typing import List
from typing import Optional

import typer
from opentelemetry import trace
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace.export import ConsoleSpanExporter
from requests.exceptions import HTTPError
from requests.exceptions import JSONDecodeError
from rich.prompt import Confirm
from rich.syntax import Syntax

from anaconda_auth import __version__
from anaconda_auth.actions import login
from anaconda_auth.actions import logout
from anaconda_auth.client import BaseClient
from anaconda_auth.config import AnacondaAuthSite
from anaconda_auth.config import AnacondaAuthSitesConfig
from anaconda_auth.exceptions import TokenExpiredError
from anaconda_auth.exceptions import UnknownSiteName
from anaconda_auth.token import TokenInfo
from anaconda_auth.token import TokenNotFoundError
from anaconda_cli_base.config import anaconda_config_path
from anaconda_cli_base.console import console
from anaconda_cli_base.exceptions import register_error_handler


def anaconda_span_details_callback(session, request):
    """
    Checks if the session is a BaseClient and adds
    custom attributes to the span if it is.
    """

    if isinstance(session, BaseClient):
        attributes = {
            "client.domain": getattr(session.config, "domain", "unknown"),
            "client.base_uri": getattr(session, "_base_uri", "unknown"),
            "client.api_version": getattr(session, "api_version", "unknown"),
        }

        return None, attributes

    return None, {}


def setup_opentelemetry() -> TracerProvider:
    """Configures OTel and instruments the requests library."""

    provider = TracerProvider()

    processor = BatchSpanProcessor(ConsoleSpanExporter())
    provider.add_span_processor(processor)

    trace.set_tracer_provider(provider)

    RequestsInstrumentor().instrument(
        span_details_callback=anaconda_span_details_callback
    )

    return provider


def _continue_with_login() -> int:
    if sys.stdout.isatty():
        do_login = Confirm.ask("Continue with interactive login?", choices=["y", "n"])
        if do_login:
            login()
            return -1
        else:
            console.print(
                dedent(
                    """
                    To configure your credentials you can run
                      [green]anaconda login --at anaconda.com[/green]

                    or set your API key using the [green]ANACONDA_AUTH_API_KEY[/green] env var

                    or set
                    """
                )
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


def _obtain_site_config(at: Optional[str] = None) -> AnacondaAuthSite:
    try:
        config = AnacondaAuthSitesConfig.load_site(site=at)
        return config
    except UnknownSiteName as e:
        console.print(e.args[0])
        raise typer.Abort(1)


app = typer.Typer(
    name="auth",
    add_completion=False,
    help="anaconda.com auth commands",
    context_settings={
        "allow_extra_args": True,
        "ignore_unknown_options": True,
        "help_option_names": ["--help", "-h"],
    },
)


@app.callback(
    invoke_without_command=True,
    no_args_is_help=False,
)
def main(
    ctx: typer.Context,
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
    extra_args: Optional[List[str]] = typer.Argument(
        default=None, hidden=True, metavar=""
    ),
) -> None:
    provider = None
    try:
        provider = setup_opentelemetry()

        tracer = trace.get_tracer("anaconda-auth.cli")

        if version:
            console.print(
                f"anaconda-auth, version [cyan]{__version__}[/cyan]",
                style="bold green",
            )
            raise typer.Exit()

        # We have to manually handle subcommands due the the handling of the auth subcommand
        # as a top-level subcommand in anaconda-client
        extra_args = extra_args or []
        if extra_args:
            subcommand_name = extra_args[0]
        else:
            subcommand_name = None

        # Extract the subcommands attached to the app. Use dynamic loading just to be safe,
        # because static typing shows this to be invalid.
        subcommands_dict = getattr(ctx.command, "commands", {})

        if cmd := subcommands_dict.get(subcommand_name):
            with tracer.start_as_current_span(
                f"cmd.{subcommand_name}",
            ) as span:
                span.set_attribute("command.name", subcommand_name)
                span.set_attribute("command.args", " ".join(extra_args[1:]))

                if ctx.params:
                    for key, value in ctx.params.items():
                        # Only log non-None values
                        if value is not None:
                            # We must convert all values to str, int, float, or bool
                            # str() is a safe fallback for most simple types
                            if not isinstance(value, (str, int, float, bool)):
                                value = str(value)

                            span.set_attribute(f"command.param.{key}", value)

                try:
                    cmd.main(extra_args[1:], standalone_mode=False, parent=ctx)

                    span.set_status(trace.StatusCode.OK)

                except Exception as e:
                    span.set_status(trace.Status(trace.StatusCode.ERROR, str(e)))
                    span.record_exception(e)

                    raise e

            return

        has_legacy_options = any(
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

        if has_legacy_options or subcommand_name:
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
            return

        # No subcommand was given, so we print help
        console.print(ctx.get_help())
    finally:
        if provider:
            provider.shutdown()


@app.command("login")
def auth_login(
    force: bool = False, ssl_verify: bool = True, at: Optional[str] = None
) -> None:
    """Login"""
    try:
        config = _obtain_site_config(at)

        auth_domain = config.domain
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

    login(config=config, force=force, ssl_verify=ssl_verify)


@app.command(name="whoami")
def auth_info(at: Optional[str] = None) -> None:
    """Display information about the currently signed-in user"""
    config = _obtain_site_config(at)
    client = BaseClient(site=config)
    response = client.get("/api/account")
    response.raise_for_status()
    console.print("Your anaconda.com info:")
    console.print_json(data=response.json(), indent=2, sort_keys=True)


@app.command(name="api-key")
def auth_key(at: Optional[str] = None) -> None:
    """Display API Key for signed-in user"""
    config = _obtain_site_config(at)

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
def auth_logout(at: Optional[str] = None) -> None:
    """Logout"""
    config = _obtain_site_config(at)
    logout(config=config)
