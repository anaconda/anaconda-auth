import json as json_mod
from typing import Optional

import typer

from anaconda_cloud_cli import console

from anaconda_cloud_auth import Client
from anaconda_cloud_auth import login
from anaconda_cloud_auth import logout

app = typer.Typer(add_completion=False)


@app.command(name="login")
def auth_login(
    ory: bool = typer.Option(False), simple: bool = typer.Option(False)
) -> None:
    login(use_ory=ory, simple=simple)
    console.print("Successfully logged into Anaconda Cloud", style="green")


@app.command(name="logout")
def auth_logout() -> None:
    token_info = logout()
    if token_info is None:
        console.print("No token found, nothing to do to logout.")
        raise typer.Exit()
    console.print("Successfully logged out of Anaconda Cloud", style="green")


@app.command(name="info")
def auth_info() -> None:
    client = Client()
    response = client.get("/api/account")
    console.print("Your Anaconda Cloud info:")
    console.print(response.json())


@app.command(name="request")
def app_request(
    url: str,
    method: str = typer.Option("GET"),
    json: str = typer.Option(None),
    debug: bool = typer.Option(False, is_flag=True),
    auth: bool = typer.Option(True, is_flag=True),
    token: Optional[str] = typer.Option(None),
) -> None:
    kwargs = {} if url.startswith("/") else dict(base_url=None)

    client = Client(**kwargs)
    if not auth:
        client.auth = None

    headers = {"Authorization": f"Bearer {token}"} if token else None
    json = json_mod.loads(json) if json else None

    response = client.request(method=method, url=url, json=json, headers=headers)
    if debug:
        console.print(f"Request headers: {response.request.headers}")
        console.print(f"Status code: {response.status_code}")
        console.print(f"Response headers: {response.headers}")
        console.print("Response data:")

    try:
        data = response.json()
    except json_mod.JSONDecodeError:
        pass
    else:
        console.print(data)
