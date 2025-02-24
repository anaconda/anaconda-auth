from typing import Optional

import typer

from anaconda_auth._conda import repo_config
from anaconda_auth.actions import _do_auth_flow
from anaconda_auth.client import BaseClient
from anaconda_auth.exceptions import TokenNotFoundError
from anaconda_auth.token import TokenInfo
from anaconda_cli_base import console

app = typer.Typer(name="token")


def _get_client() -> BaseClient:
    """Perform browser-based auth flow and create a new Client instance to make authenticated HTTP requests."""
    access_token = _do_auth_flow()
    return BaseClient(api_key=access_token)


def _set_repo_token(org_name: str, token: Optional[str]) -> None:
    # TODO: Construct this from the config
    domain = "repo.anaconda.cloud"
    try:
        token_info = TokenInfo.load(domain)
    except TokenNotFoundError:
        token_info = TokenInfo(domain=domain)

    if token is not None:
        token_info.set_repo_token(org_name=org_name, token=token)
    else:
        token_info.delete_repo_token(org_name=org_name)
    token_info.save()


@app.callback(invoke_without_command=True, no_args_is_help=True)
def main() -> None:
    """Manage your Anaconda repo tokens."""


@app.command(name="list")
def list_tokens():
    # The contents of this
    tokens = repo_config.token_list()
    if not tokens:
        raise typer.Abort(f"No tokens have been configured for {repo_config.REPO_URL}")

    console.print("Listing tokens")
    for url, token in tokens.items():
        console.print(url, token)


@app.command(name="install")
def install_token(org_name: str = typer.Option("", "-o", "--org-name")):
    """Create and install a new repository token."""
    if not org_name:
        # TODO: We should try to load this dynamically and present a picker
        console.print("Must explicitly provide an [cyan]--org-name[/cyan] option")
        raise typer.Abort()

    client = _get_client()

    response = client.put(
        f"/api/organizations/{org_name}/ce/current-token",
        json={"confirm": "yes"},
    )

    console.print(response.json())

    token = response.json()["token"]
    expires_at = response.json()["expires_at"]

    console.print(
        f"Your conda token is: [cyan]{token}[/cyan], which expires [cyan]{expires_at}[/cyan]"
    )

    try:
        repo_config.validate_token(token, no_ssl_verify=False)
    except repo_config.CondaTokenError as e:
        raise typer.Abort(e)

    _set_repo_token(org_name=org_name, token=token)
    console.print("Success! Your token was validated and conda has been configured.")


@app.command(name="uninstall")
def uninstall_token(org_name: str = typer.Option("", "-o", "--org-name")):
    """Uninstall a repository token for a specific organization."""
    # TODO: Add --all option
    if not org_name:
        # TODO: We should try to load this dynamically and present a picker
        console.print("Must explicitly provide an [cyan]--org-name[/cyan] option")
        raise typer.Abort()
    _set_repo_token(org_name=org_name, token=None)
