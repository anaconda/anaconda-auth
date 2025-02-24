from __future__ import annotations

from datetime import datetime

import typer
from pydantic import BaseModel
from rich.table import Table

from anaconda_auth.actions import _do_auth_flow
from anaconda_auth.client import BaseClient
from anaconda_auth.exceptions import TokenNotFoundError
from anaconda_auth.token import TokenInfo
from anaconda_cli_base import console

app = typer.Typer(name="token")


class TokenResponse(BaseModel):
    token: str
    expires_at: datetime


class RepoAPIClient(BaseClient):
    def __init__(self) -> None:
        access_token = _do_auth_flow()
        super().__init__(api_key=access_token)

    def create_repo_token(self, org_name: str) -> TokenResponse:
        response = self.put(
            f"/api/organizations/{org_name}/ce/current-token",
            json={"confirm": "yes"},
        )
        return TokenResponse(**response.json())


def _set_repo_token(org_name: str, token: str) -> None:
    # TODO: Construct this from the config
    domain = "repo.anaconda.cloud"
    try:
        token_info = TokenInfo.load(domain)
    except TokenNotFoundError:
        token_info = TokenInfo(domain=domain)

    token_info.set_repo_token(org_name, token)
    token_info.save()


@app.callback(invoke_without_command=True, no_args_is_help=True)
def main() -> None:
    """Manage your Anaconda repo tokens."""


@app.command(name="list")
def list_tokens() -> None:
    from anaconda_auth._conda.repo_config import token_list

    tokens = token_list()

    if not tokens:
        console.print("No repo tokens are installed. Run `anaconda token install`.")
        raise typer.Abort()

    _print_repo_token_table(tokens)


def _print_repo_token_table(tokens: dict[str, str]) -> None:
    table = Table(title="Anaconda Repository Tokens", title_style="green")

    table.add_column("Channel URL")
    table.add_column("Token")

    for url, token in tokens.items():
        table.add_row(url, token)

    console.print(table)


@app.command(name="install")
def install_token() -> None:
    org_name = "anacondiacsbusiness"

    client = RepoAPIClient()
    response = client.create_repo_token(org_name=org_name)

    console.print(
        f"Your conda token is: [cyan]{response.token}[/cyan], which expires [cyan]{response.expires_at}[/cyan]"
    )

    from anaconda_auth._conda import repo_config

    try:
        repo_config.validate_token(response.token, no_ssl_verify=False)
    except repo_config.CondaTokenError as e:
        raise typer.Abort(e)

    _set_repo_token(org_name=org_name, token=response.token)
    console.print("Success! Your token was validated and conda has been configured.")
