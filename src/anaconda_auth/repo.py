from typing import NamedTuple
from typing import Optional

import typer

from anaconda_auth._conda import repo_config
from anaconda_auth._conda.conda_token import token_set
from anaconda_auth.actions import _do_auth_flow
from anaconda_auth.client import BaseClient
from anaconda_cli_base import console

app = typer.Typer(name="token")


class Args(NamedTuple):
    token: str
    no_ssl_verify: bool = False
    system: bool = False
    env: bool = True
    file: Optional[str] = None
    include_archive_channels: list[str] = []
    enable_signature_verification: bool = False


def _get_client() -> BaseClient:
    """Perform browser-based auth flow and create a new Client instance to make authenticated HTTP requests."""
    access_token = _do_auth_flow()
    return BaseClient(api_key=access_token)


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
def install_token():
    client = _get_client()

    response = client.put(
        "/api/organizations/anacondiacsbusiness/ce/current-token",
        json={"confirm": "yes"},
    )

    console.print(response.json())

    token = response.json()["token"]

    console.print(f"Your conda token is: [cyan]{token}[/cyan]")

    token_set(Args(token=token))
