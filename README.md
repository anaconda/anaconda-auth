# anaconda-auth

A client library for Anaconda APIs to authenticate and securely store API keys.
This library is used by other client packages to provide a centralized auth
capability for the ecosystem. You will need to use this package to log in to anaconda.com
before utilizing many of the other client packages.

This package provides a [requests](https://requests.readthedocs.io/en/latest/)
client class that handles loading the API key for requests made to Anaconda services.

This package provides a [Panel OAuth plugin](https://panel.holoviz.org/how_to/authentication/configuration.html)
called `anaconda_auth`.

## Installation

```text
conda install anaconda-auth
```

## Usage

The primary usage of this package is to provide CLI actions for login, logout, user information, and api-keys
to Anaconda API Services.

```text
❯ anaconda auth

 Usage: anaconda auth [OPTIONS] COMMAND [ARGS]...

 Anaconda auth commands

╭─ Options ──────────────────────────────────────────────────────────────────────────────────╮
│ --version  -V                                                                              │
│ --help               Show this message and exit.                                           │
╰────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ─────────────────────────────────────────────────────────────────────────────────╮
│ api-key   Display API Key for signed-in user                                               │
│ login     Login                                                                            │
│ logout    Logout                                                                           │
│ whoami    Display information about the currently signed-in user                           │
╰────────────────────────────────────────────────────────────────────────────────────────────╯
```

## Configuration

You can configure `anaconda-auth` by either:

1. Setting parameters in the `plugin.auth` section of the `~/.anaconda/config.toml` file.
1. Setting one or more `ANACONDA_AUTH_` environment variables or using a `.env` file in your working directory.

`ANACONDA_AUTH_` env vars or a `.env` file take precedence over the `~/.anaconda/config.toml` file.

### Anaconda parameters

The following parameters in the `plugin.auth` section control the login actions and API requests to Anaconda Services.

| Parameter | Env variable | Description | Default value |
|-|-|-|-|
| `domain` | `ANACONDA_AUTH_DOMAIN` | Authentication and API request domain | `"anaconda.com"` |
| `ssl_verify` | `ANACONDA_AUTH_SSL_VERIFY` | SSL verification for all requests | `True` |
| `preferred_token_storage` | `ANACONDA_AUTH_PREFERRED_TOKEN_STORAGE` | Where to store the login token; can be `"anaconda-keyring"` or `"system"` | `"anaconda-keyring"` |
| `api_key` | `ANACONDA_AUTH_API_KEY` | API key; if `None`, defaults to keyring storage | `None` |
| `extra_headers` | `ANACONDA_AUTH_EXTRA_HEADERS` | Extra request headers in JSON format | `None` |

### Example

Here's an example `~/.anaconda/config.toml` where SSL verification is turned
off for login and API requests and where the preferred token storage is `anaconda-keyring`.

```toml
[plugin.auth]
ssl_verify = false
preferred_token_storage = "system"
```

## API Keys and tokens

When you `login` with `anaconda-auth`, an auth token is stored in the preferred keyring storage location and is
deleted when you run `logout`. The auth token will need to be renewed once a year.

The `preferred_storage` configuration parameter in the `plugin.auth` section of the `config.toml` file takes two
possible values:

| Storage location | Description |
|-|-|
| `"system"` | Use the system keyring, if available. Otherwise, use `anaconda-keyring` |
| `"anaconda-keyring"` | A file-based keyring at `~/.anaconda/keyring` |

`"anaconda-keyring"` is the default value.

### Non-interactive use

If you want to utilize Anaconda Services on a system where you do not have interactive access to a browser to
use the `login` command, you have two options:

1. On a system where you can log in, use `anaconda auth api-key` command to print the API key to the terminal. You can then
utilize the API key on the non-interactive system with the `ANACONDA_AUTH_API_KEY` env var (or in a `.env` file) or set
the `key` parameter in the `plugin.auth` section of the `~/.anaconda/config.toml` file.
1. With `preferred_token_storage` set to `"anaconda-keyring"`, run the `login` command to create the `~/.anaconda/keyring`
file. Then, copy `~/.anaconda/keyring` to the non-interactive system.

## Python API

```python
from anaconda_auth import login

login()
```

The `login()` function initiates a browser-based login flow. It will automatically
open your browser and, once you have completed the login flow, it will store an
API key on your system.

Typically, these API keys will have a one year expiration, so you will only need
to log in once and requests using the client class will read the token from the
keyring storage.

If you call `login()` while there is a valid (non-expired) API key, no action is
taken. You can replace the valid API key with `login(force=True)`.

To remove the API key from your keyring storage, use the `logout()` function.

```python
from anaconda_auth import logout

logout()
```

### API requests

The BaseClient class is a subclass of [requests.Session](https://requests.readthedocs.io/en/latest/user/advanced/#session-objects).
It will attempt to load the API key from the keyring on each request unless overridden
by the `api_key` argument.

The BaseClient class can be used for non-authenticated requests even when
the user has not logged in or provided an API in the request.

```python
from anaconda_auth.client import BaseClient

client = BaseClient()

response = client.get("/api/<endpoint>")
response.raise_for_status()
print(response.json())
```

BaseClient accepts the following optional arguments.

* `domain`: Domain to use for requests, defaults to `anaconda.com`
* `ssl_verify`: Enable SSL verification, defaults to `True`
* `api_key`: API key to use for requests, if unspecified, uses token set by `anaconda login`
* `user_agent`: Defaults to `anaconda-auth/<package-version>`
* `api_version`: Requested API version, defaults to latest available from the domain
* `extra_headers`: Dictionary or JSON string of extra headers to send in requests

To create a Client class specific to your package, subclass BaseClient and set
an appropriate user-agent and API version for your needs.

```python
from anaconda_auth.client import BaseClient
class Client(BaseClient):
    _user_agent = "anaconda-<package>/<version>"
    _api_version = "<api-version>"
```

## CLI Error handlers

This plugin defines an [error handler](https://github.com/anaconda/anaconda-cli-base#error-handling) for the `HTTPError` exception when using `.raise_for_status()` on a response
using BaseClient or subclasses of BaseClient. Errors are not caught automatically when using the BaseClient
or subclasses outside of `anaconda` CLI subcommands.

### Login required

For the following cases, the user is running the CLI command interactively and is asked if they wish to continue with
interactive login. Once completed, the command will be re-tried.

* `TokenNotFoundError`: The subcommand requested to load the token from the keyring, but none were present.
* `TokenExpiredError`: The token was successfully loaded but has expired.
* `AuthenticationMissing`: Derived from `requests.exceptions.HTTPError`, the request was made without an API key or token to an endpoint that requires authentication.
* `InvalidAuthentication`: Derived from `requests.exceptions.HTTPError`, the request was made using an API key or token, but Anaconda determined that the API was invalid.

Here's an example demonstrating that the user has not previously run `anaconda login` but attempted a CLI command that at some point requires authentication. By typing `y`, the login action is triggered and their browser will open.

```text
❯ anaconda auth api-key
TokenNotFoundError: Login is required to complete this action.
Continue with interactive login? [y/n]: y
<api-key>
```

If the user typed `n` or the command was not run on an interactive terminal, an error message is shown instructing
the user how to log in or configure the API key.

```text
❯ anaconda auth whoami
AuthenticationMissingError: Login is required to complete this action.
Continue with interactive login? [y/n]: n

To configure your credentials you can run
  anaconda login --at anaconda.com

or set your API key using the ANACONDA_AUTH_API_KEY env var

or set

[plugin.auth]
api_key = "<api-key>"

in ~/.anaconda/config.toml

To see a more detailed error message run the command again as
  anaconda --verbose auth whoami
```

### HTTPError

In addition to the two special cases above, all HTTPError exceptions thrown during CLI subcommands will be handled
to provide the error code and reason.

For example, a subcommand using BaseClient or a subclass of it may make a bad request.

```python
@plugin.subcommand('do-something')
def do_something(inputs: Annotated[Any, typer.Argument()]):
    client = Client()
    res = client.post('api/something', data=inputs)
    res.raise_for_status()
```

For this example subcommand, the user may provide incorrect inputs that are passed to the endpoint. By using
`.raise_for_status()`, the error is passed along to the CLI user and a short response is printed.

```text
> anaconda plugin do-something 'input-data'
HTTPError: 422 Client Error: Unprocessable Entity for url: https://anaconda.com/api/something

To see a more detailed error message run the command again as
  anaconda --verbose plugin do-something
```

## Panel OAuth Provider

In order to use the `anaconda_auth` auth plugin, you will need an OAuth client
ID (key) and secret. The client must be configured as follows:

```text
Set scopes: offline_access, openid, email, profile
Set redirect url to http://localhost:5006
Set grant type: Authorization Code
Set response types: ID Token, Token, Code
Set access token type: JWT
Set Authentication Method: HTTP Body
```

To run the app with the anaconda_auth auth provider, you will need to set several
environment variables or command-line arguments. See the
[Panel OAuth documentation](https://panel.holoviz.org/how_to/authentication/configuration.html)
for more details.

```text
PANEL_OAUTH_PROVIDER=anaconda_auth or --oauth-provider anaconda_auth
PANEL_OAUTH_KEY=<key>               or --oauth-key=<key>
PANEL_OAUTH_SECRET=<secret>         or --oauth-secret=<key>
PANEL_COOKIE_SECRET=<cookie-name>   or --cookie-secret=<value>
PANEL_OAUTH_REFRESH_TOKENS=1        or --oauth-refresh-tokens
PANEL_OAUTH_OPTIONAL=1              or --oauth-optional
```

```text
panel serve <arguments> ...
```

If you do not specify the `.env` file, the production configuration should be the default.
Please file an issue if you see any errors.

## Setup for development

Ensure you have `conda` installed.
Then run:

```shell
make setup
```

### Run the unit tests

```shell
make test
```

### Run the unit tests across isolated environments with tox

```shell
make tox
```
