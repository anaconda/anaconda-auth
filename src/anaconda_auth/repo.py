from __future__ import annotations

import typer

from anaconda_cli_base import console

app = typer.Typer(name="token")


@app.callback(invoke_without_command=True, no_args_is_help=True)
def main() -> None:
    """Manage your Anaconda repo tokens."""


@app.command(name="list")
def list_tokens() -> None:
    from anaconda_auth._conda import repo_config

    # The contents of this
    tokens = repo_config.token_list()
    if not tokens:
        console.print("No repo tokens are installed. Run `anaconda token install`.")
        raise typer.Abort()

    console.print("Listing tokens")
    for url, token in tokens.items():
        console.print(url, token)
