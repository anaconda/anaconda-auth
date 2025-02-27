from __future__ import annotations

from datetime import datetime
from uuid import UUID

import typer
from pydantic import BaseModel
from rich.prompt import Confirm
from rich.table import Table

from anaconda_auth.actions import _do_auth_flow
from anaconda_auth.client import BaseClient
from anaconda_auth.token import RepoToken
from anaconda_auth.token import TokenInfo
from anaconda_cli_base import console
from anaconda_cli_base.console import select_from_list

app = typer.Typer(name="token")


class TokenInfoResponse(BaseModel):
    id: UUID
    expires_at: datetime


class TokenCreateResponse(BaseModel):
    token: str
    expires_at: datetime


class OrganizationData(BaseModel):
    name: str
    title: str


class RepoAPIClient(BaseClient):
    def __init__(self) -> None:
        access_token = _do_auth_flow()
        super().__init__(api_key=access_token)

    def get_repo_token_info(self, org_name: str) -> TokenInfoResponse | None:
        """Return the token information, if it exists.

        Args:
            org_name: The name of the organization.

        Returns:
            The token information, including its id and expiration date, or
            None if a token doesn't exist.
        """

        response = self.get(
            f"/api/organizations/{org_name}/ce/current-token",
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return TokenInfoResponse(**response.json())

    def create_repo_token(self, org_name: str) -> TokenCreateResponse:
        """Create a new repo token.

        Args:
            org_name: The name of the organization.

        Returns:
            The token information, including its value and expiration date.
        """
        response = self.put(
            f"/api/organizations/{org_name}/ce/current-token",
            json={"confirm": "yes"},
        )
        return TokenCreateResponse(**response.json())

    def get_organizations_for_user(self) -> list[OrganizationData]:
        """Get a list of all organizations the user belongs to."""
        response = self.get("/api/organizations/my")
        response.raise_for_status()
        data = response.json()
        return [OrganizationData(**item) for item in data]


def _print_repo_token_table(
    tokens: list[RepoToken], legacy_tokens: dict[str, str]
) -> None:
    table = Table(title="Anaconda Repository Tokens", title_style="green")

    table.add_column("Organization")
    table.add_column("Channel URL")
    table.add_column("Token")

    for repo_token in tokens:
        table.add_row(repo_token.org_name, None, repo_token.token)

    for url, token in legacy_tokens.items():
        table.add_row(None, url, token)

    console.print(table)


def _select_org_name(client: RepoAPIClient) -> str:
    organizations = client.get_organizations_for_user()

    if not organizations:
        console.print("No organizations found.")
        raise typer.Abort()

    if len(organizations) == 1:
        org_name = organizations[0].name
        console.print(
            f"Only one organization found, automatically selecting: {org_name}"
        )
        return org_name

    name_map = {}
    choices = []
    for org in organizations:
        key = f"{org.title} ([cyan]{org.name}[/cyan])"
        name_map[key] = org.name
        choices.append(key)

    org_title = select_from_list(
        "Please select an organization:",
        choices=choices,
    )
    return name_map[org_title]


@app.callback(invoke_without_command=True, no_args_is_help=True)
def main() -> None:
    """Manage your Anaconda repo tokens."""


@app.command(name="list")
def list_tokens() -> None:
    """List all installed repository tokens."""
    from anaconda_auth._conda.repo_config import token_list

    tokens = token_list()

    token_info = TokenInfo.load()
    repo_tokens = token_info.repo_tokens

    if not tokens:
        console.print("No repo tokens are installed. Run `anaconda token install`.")
        raise typer.Abort()

    _print_repo_token_table(tokens=repo_tokens, legacy_tokens=tokens)


@app.command(name="install")
def install_token(org_name: str = typer.Option("", "-o", "--org")) -> None:
    """Create and install a new repository token."""
    client = RepoAPIClient()

    if not org_name:
        org_name = _select_org_name(client)

    existing_token_info = client.get_repo_token_info(org_name=org_name)

    if existing_token_info is not None:
        console.print(
            f"An existing token already exists for the organization [cyan]{org_name}[/cyan]."
        )
        should_continue = Confirm.ask(
            "Would you like to issue a new token?",
            default=True,
        )
        if not should_continue:
            raise typer.Abort()

    response = client.create_repo_token(org_name=org_name)

    console.print(
        f"Your conda token is: [cyan]{response.token}[/cyan], which expires [cyan]{response.expires_at}[/cyan]"
    )

    from anaconda_auth._conda import repo_config

    try:
        repo_config.validate_token(response.token, no_ssl_verify=False)
    except repo_config.CondaTokenError as e:
        raise typer.Abort(e)

    token_info = TokenInfo.load(create=True)
    token_info.set_repo_token(org_name, response.token)
    token_info.save()

    console.print("Success! Your token was validated and conda has been configured.")


@app.command(name="uninstall")
def uninstall_token(org_name: str = typer.Option("", "-o", "--org")) -> None:
    """Uninstall a repository token for a specific organization."""
    # TODO: Add --all option
    if not org_name:
        # TODO: We should try to load this dynamically and present a picker
        console.print("Must explicitly provide an [cyan]--org[/cyan] option")
        raise typer.Abort()

    token_info = TokenInfo.load()
    token_info.delete_repo_token(org_name=org_name)
    token_info.save()

    console.print(
        f"Successfully deleted token for organization: [cyan]{org_name}[/cyan]"
    )
