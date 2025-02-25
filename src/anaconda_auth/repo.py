from __future__ import annotations

import typer
from rich.table import Table

from anaconda_cli_base import console

app = typer.Typer(name="token")


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
