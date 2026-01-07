import json
import os
import sys
import warnings
from textwrap import dedent
from typing import List
from typing import Optional

import typer
from requests.exceptions import HTTPError
from requests.exceptions import JSONDecodeError
from rich.prompt import Confirm
from rich.syntax import Syntax
from rich.table import Table

from anaconda_auth import __version__
from anaconda_auth.actions import login
from anaconda_auth.actions import logout
from anaconda_auth.client import BaseClient
from anaconda_auth.config import AnacondaAuthConfig
from anaconda_auth.config import AnacondaAuthSite
from anaconda_auth.config import AnacondaAuthSitesConfig
from anaconda_auth.config import AnacondaCloudConfig
from anaconda_auth.exceptions import TokenExpiredError
from anaconda_auth.token import TokenInfo
from anaconda_auth.token import TokenNotFoundError
from anaconda_cli_base.config import anaconda_config_path
from anaconda_cli_base.console import console
from anaconda_cli_base.exceptions import register_error_handler

CHECK_MARK = "[bold green]✔︎[/bold green]"


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


def _override_default_site(at: Optional[str] = None) -> None:
    if at:
        os.environ["ANACONDA_DEFAULT_SITE"] = at


app = typer.Typer(
    name="auth",
    add_completion=False,
    help="Manage your Anaconda authentication",
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

    # If the subcommand is known, then we delegate to the actual functions defined in this module
    if cmd := subcommands_dict.get(subcommand_name):
        cmd.main(
            extra_args[1:], prog_name=subcommand_name, standalone_mode=False, parent=ctx
        )
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


@app.command("login")
def auth_login(
    force: bool = False,
    ssl_verify: Optional[bool] = typer.Option(None, "--ssl-verify/--no-ssl-verify"),
    at: Optional[str] = None,
) -> None:
    """Login"""
    _override_default_site(at)
    try:
        token_info = TokenInfo.load()
        domain = token_info.domain
        if token_info.expired:
            console.print(f"Your API key has expired, logging into {domain}")
            login(force=True, ssl_verify=ssl_verify)
            raise typer.Exit()
    except TokenNotFoundError:
        pass  # Proceed to login
    else:
        force = force or Confirm.ask(
            f"You are already logged into Anaconda ({domain}). Would you like to force a new login?",
            default=False,
        )
        if not force:
            raise typer.Exit()

    login(force=force, ssl_verify=ssl_verify)


@app.command(name="whoami")
def auth_info(at: Optional[str] = None) -> None:
    """Display information about the currently signed-in user"""
    _override_default_site(at)
    client = BaseClient()
    response = client.get("/api/account")
    response.raise_for_status()
    console.print(f"Your info ({client.config.domain}):")
    console.print_json(data=response.json(), indent=2, sort_keys=True)


@app.command(name="api-key")
def auth_key(at: Optional[str] = None) -> None:
    """Display API Key for signed-in user"""
    _override_default_site(at)
    token_info = TokenInfo.load()
    if not token_info.expired:
        print(token_info.api_key)
        return
    else:
        raise TokenExpiredError()


@app.command(name="logout")
def auth_logout(at: Optional[str] = None) -> None:
    """Logout"""
    _override_default_site(at)
    logout()


def _protect_secrets():
    # Do not allow these to leak into the config.toml
    # * condarc config
    # * env vars (including .env file)
    # * secrets
    AnacondaAuthConfig.model_config.update(
        env_file=None,
        env_prefix="__ANACONDA_HIDDEN_AUTH_",
        secrets_dir=None,
        disable_conda_context=True,
    )

    AnacondaCloudConfig.model_config.update(
        env_file=None,
        env_prefix="__ANACONDA_HIDDEN_CLOUD_",
        secrets_dir=None,
        disable_conda_context=True,
    )

    AnacondaAuthSitesConfig.model_config.update(
        env_file=None,
        env_prefix="__ANACONDA_HIDDEN_SITES_",
        secrets_dir=None,
        disable_conda_context=True,
    )


sites_app = typer.Typer(
    name="sites",
    add_completion=False,
    help="Manage your Anaconda site configuration",
    context_settings={
        "allow_extra_args": True,
        "ignore_unknown_options": True,
        "help_option_names": ["--help", "-h"],
    },
)


@sites_app.command(name="list")
def sites_list() -> None:
    """List configured sites by name and domain."""
    sites_config = AnacondaAuthSitesConfig()

    table = Table("Site name", "Domain name", "Default site", header_style="bold green")

    for name, site in sites_config.sites.items():
        is_default = CHECK_MARK if name == sites_config.default_site else ""
        table.add_row(name, site.domain, is_default)

    console.print(table)


@sites_app.command(name="show")
def sites_show(
    site: Optional[str] = typer.Argument(
        default=None,
        help="Choose configured site name or domain name. If unspecified will show the configured default site.",
    ),
    all: Optional[bool] = typer.Option(
        False, "--all", help="Show all site configurations"
    ),
    show_hidden: bool = typer.Option(False, help="Show hidden fields"),
) -> None:
    """Show the site configuration for the default site or look up by the provided name or domain."""

    hidden = {
        "api_key",
        "auth_domain_override",
        "client_id",
        "hash_hostname",
        "keyring",
        "preferred_token_storage",
        "login_success_path",
        "login_error_path",
        "openid_config_path",
        "oidc_request_headers",
        "redirect_uri",
    }

    exclude = None if show_hidden else hidden

    if all:
        sites = AnacondaAuthSitesConfig()
        all_sites = {
            config.site: config.model_dump(exclude=exclude)
            for config in sites.sites.root.values()
        }
        console.print_json(data=all_sites)
    else:
        config = AnacondaAuthSitesConfig.load_site(site=site)
        data = config.model_dump(exclude=exclude)
        data = {"site": config.site, **data}
        console.print_json(data=data)


def _confirm_write(
    sites: AnacondaAuthSitesConfig,
    yes: Optional[bool],
    preserve_existing_keys: bool = True,
) -> None:
    if yes is True:
        sites.write_config(preserve_existing_keys=preserve_existing_keys)
    elif yes is False:
        sites.write_config(dry_run=True, preserve_existing_keys=preserve_existing_keys)
    else:
        sites.write_config(dry_run=True, preserve_existing_keys=preserve_existing_keys)
        if Confirm.ask("Confirm:"):
            sites.write_config(preserve_existing_keys=preserve_existing_keys)


def sites_add_or_modify(
    ctx: typer.Context,
    domain: Optional[str] = typer.Option(
        default=None, help="Domain name for site, defaults to 'anaconda.com'"
    ),
    name: Optional[str] = typer.Option(
        default=None, help="Name for site, defaults to domain if not supplied"
    ),
    default: bool = typer.Option(default=False, help="Set this site as default"),
    api_key: Optional[str] = typer.Option(
        default=None,
        help=f"API key for site. CAUTION: this will get written to {anaconda_config_path()}",
    ),
    preferred_token_storage: Optional[str] = typer.Option(default=None, hidden=True),
    auth_domain_override: Optional[str] = typer.Option(default=None, hidden=True),
    keyring: Optional[str] = typer.Option(default=None, hidden=True),
    ssl_verify: bool = True,
    use_truststore: bool = False,
    extra_headers: Optional[str] = typer.Option(
        default=None, help="Extra headers in JSON format to use for all requests"
    ),
    client_id: Optional[str] = typer.Option(default=None, hidden=True),
    redirect_uri: str = typer.Option(default=None, hidden=True),
    openid_config_path: Optional[str] = typer.Option(default=None, hidden=True),
    oidc_request_headers: Optional[str] = typer.Option(default=None, hidden=True),
    login_success_path: Optional[str] = typer.Option(default=None, hidden=True),
    login_error_path: Optional[str] = typer.Option(default=None, hidden=True),
    use_unified_repo_api_key: Optional[bool] = typer.Option(
        None, "--use-unified-repo-api-key/--no-use-unified-repo-api-key"
    ),
    hash_hostname: Optional[bool] = typer.Option(
        None, "--hash-host-name/--no-hash-host-name", hidden=True
    ),
    proxy_servers: Optional[str] = typer.Option(
        default=None, help="JSON string of proxy server mapping"
    ),
    client_cert: Optional[str] = None,
    client_cert_key: Optional[str] = None,
    use_device_flow: Optional[bool] = typer.Option(
        None, "--use-device-flow/--no-use-device-flow"
    ),
    disable_conda_auto_config: Optional[bool] = typer.Option(
        None, "--disable-conda-auto-config/--no-disable-conda-auto-config"
    ),
    replace_anaconda_com: Optional[bool] = typer.Option(
        True, help="Remove the site named 'anaconda.com' if present"
    ),
    yes: Optional[bool] = typer.Option(
        None,
        "--yes/--dry-run",
        "-y",
        help="Confirm changes and write, use --dry-run to print diff but do not write",
    ),
) -> None:
    if use_truststore and not ssl_verify:
        raise ValueError("Cannot set both --use-truststore and --no-ssl-verify")

    kwargs = dict[str, bool | str](
        ssl_verify="truststore" if use_truststore else ssl_verify,
    )

    if name is not None:
        kwargs["site"] = name
    if domain is not None:
        kwargs["domain"] = domain
    if api_key is not None:
        msg = (
            "[bold yellow]WARNING:[/bold yellow] "
            f"Your API Key will be stored in {anaconda_config_path()} and may not be secure"
        )
        console.print(msg)
        kwargs["api_key"] = api_key
    if extra_headers is not None:
        parsed_extra_headers = json.loads(extra_headers)
        kwargs["extra_headers"] = parsed_extra_headers
    if proxy_servers is not None:
        parsed_proxy_servers = json.loads(proxy_servers)
        kwargs["proxy_servers"] = parsed_proxy_servers
    if client_cert is not None:
        kwargs["client_cert"] = client_cert
    if client_cert_key is not None:
        kwargs["client_cert_key"] = client_cert_key
    if use_device_flow is not None:
        kwargs["use_device_flow"] = use_device_flow
    if use_unified_repo_api_key is not None:
        kwargs["use_unified_repo_api_key"] = use_unified_repo_api_key
    if disable_conda_auto_config is not None:
        kwargs["disable_conda_auto_config"] = disable_conda_auto_config
    if preferred_token_storage is not None:
        kwargs["preferred_token_storage"] = preferred_token_storage
    if auth_domain_override is not None:
        kwargs["auth_domain_override"] = auth_domain_override
    if keyring is not None:
        msg = (
            "[bold yellow]WARNING:[/bold yellow] "
            f"Your Keyring contents will be stored in {anaconda_config_path()} and may not be secure"
        )
        console.print(msg)
        parsed_keyring = json.loads(keyring)
        kwargs["keyring"] = parsed_keyring
    if client_id is not None:
        kwargs["client_id"] = client_id
    if redirect_uri is not None:
        kwargs["redirect_uri"] = redirect_uri
    if openid_config_path is not None:
        kwargs["openid_config_path"] = openid_config_path
    if oidc_request_headers is not None:
        kwargs["oidc_request_headers"] = oidc_request_headers
    if login_success_path is not None:
        kwargs["login_success_path"] = login_success_path
    if login_error_path is not None:
        kwargs["login_error_path"] = login_error_path
    if hash_hostname is not None:
        kwargs["hash_hostname"] = hash_hostname

    _protect_secrets()

    sites = AnacondaAuthSitesConfig()

    if ctx.command.name == "add":
        if domain is None:
            raise ValueError("You must supply at least --domain to a add a new site")

        if name is None:
            name = domain

        if name in sites.sites:
            raise ValueError(
                f"A site with name {name} already exists, use the modify subcommand to alter it"
            )

        config = AnacondaAuthSite(**kwargs)
        sites.add(config, name=config.site)

        if replace_anaconda_com and "anaconda.com" in sites.sites.root:
            del sites.sites.root["anaconda.com"]

        if default:
            sites.default_site = config.site

    elif ctx.command.name == "modify":
        if domain is None and name is None:
            raise ValueError(
                "You must supply at least one of --domain or --name to modify a site"
            )

        key = sites.sites._find_at(name or domain)
        config = sites.sites.root[key]
        config = config.model_copy(update=kwargs)

        sites.add(config, name=config.site)

    _confirm_write(sites, yes)


sites_add = sites_app.command(
    name="add",
    no_args_is_help=True,
    help=f"Add new site configuration to {anaconda_config_path()}",
)(sites_add_or_modify)

sites_modify = sites_app.command(
    name="modify",
    no_args_is_help=True,
    help=f"Modify site configuration in {anaconda_config_path()}",
)(sites_add_or_modify)


@sites_app.command(name="remove", no_args_is_help=True)
def sites_remove(
    site: str = typer.Argument(help="Site name or domain name to remove."),
    yes: Optional[bool] = typer.Option(
        None,
        "--yes/--dry-run",
        "-y",
        help="Confirm changes and write, use --dry-run to print diff but do no write",
    ),
) -> None:
    """Remove site configuration by name or domain."""
    sites = AnacondaAuthSitesConfig()
    config = sites.sites[site]

    sites.remove(site)
    if sites.default_site == config.site:
        sites.default_site = next(iter(sites.sites))

    _confirm_write(sites, yes, preserve_existing_keys=False)
