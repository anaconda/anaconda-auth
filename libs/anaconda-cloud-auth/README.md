# anaconda-cloud-auth

A client library for Anaconda.cloud APIs to authenticate and securely store API keys.
This library is used by other Anaconda.cloud client packages to provide a centralized auth
capability for the ecosystem. You will need to use this package to login to Anaconda.cloud
before utilizing many of the other client packages.

This package provides a [requests](https://requests.readthedocs.io/en/latest/)
client class that handles loading the API key for requests made to Anaconda Cloud services.

This package provides a [Panel OAuth plugin](https://panel.holoviz.org/how_to/authentication/configuration.html)
called `anaconda_cloud`.

## Installation

```text
conda install anaconda-cloud-auth
```

## Usage

The primary usage of this package is to provide CLI actions for login, logout, user information, and api-keys
to Anaconda Cloud API Services.

```text
❯ anaconda cloud

 Usage: anaconda cloud [OPTIONS] COMMAND [ARGS]...

 Anaconda.cloud auth commands

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

You can configure `anaconda-cloud-auth` by either

1. Setting parameters in the `plugin.cloud` section of the `~/.anaconda/config.toml` file
1. Setting one or more `ANACONDA_CLOUD_` environment variables or use a `.env` file in your working directory

`ANACONDA_CLOUD_` env vars or `.env` file take precedence over the `~/.anaconda/config.toml` file.

### Anaconda Cloud parameters

The following parameters in the `plugin.cloud` section control the login actions and API requests to Anaconda Cloud Services.

| Parameter | Env variable | Description | Default value |
|-|-|-|-|
| `domain` | `ANACONDA_CLOUD_DOMAIN` | Authentication and API request domain | `"anaconda.cloud"` |
| `ssl_verify` | `ANACONDA_CLOUD_SSL_VERIFY` | SSL verification for all requests | `True` |
| `preferred_token_storage` | `ANACONDA_CLOUD_PREFERRED_TOKEN_STORAGE` | Where to store the login token, can be `"anaconda-keyring"` or `"system"` | `"anaconda-keyring"` |
| `api_key` | `ANACONDA_CLOUD_API_KEY` | API key, if `None` defaults to keyring storage | `None` |
| `extra_headers` | `ANACONDA_CLOUD_EXTRA_HEADERS` | Extra request headers in JSON format | `None` |

### Example

Here's an example `~/.anaconda/config.toml` where SSL verification is turned
off for login and API requests and the preferred token storage is `anaconda-keyring`.

```toml
[plugin.cloud]
ssl_verify = false
preferred_token_storage = "system"
```

## API Keys and tokens

When you `login` with `anaconda-cloud-auth` an auth token is stored in the preferred keyring storage location and is
deleted when you run `logout`. The auth token will need to be renewed once a year.

The `preferred_storage` configuration parameter in the `plugin.cloud` section of the config.toml file takes two
possible values

| Storage location | Description |
|-|-|
| `"system"` | Use the system keyring if available, otherwise use `anaconda-keyring` |
| `"anaconda-keyring"` | A file-based keyring at `~/.anaconda/keyring` |

`"anaconda-keyring"` is the default value.

### Non-interactive use

If you want to utilize Anaconda Cloud Services on a system where you do not have interactive access to a browser to
use the `login` command you have two options

1. Use `anaconda cloud api-key` command on a system where you can login to print the API key to the terminal. You can then
utilize the API key on the non-interactive system with the `ANACONDA_CLOUD_API_KEY` env var (or in `.env` file) or set
the `key` parameter in the `plugin.cloud_api` section of the `~/.anaconda/config.toml` file.
1. With `preferred_token_storage` set to `"anaconda-keyring"` run the `login` command to create the `~/.anaconda/keyring`
file. Then copy `~/.anaconda/keyring` to the non-interactive system.

## Python API

```python
from anaconda_cloud_auth import login

login()
```

The `login()` function initiates a browser-based login flow. It will automatically
open your browser and once you have completed the login flow it will store an
API key on your system.

Typically, these API keys will have a one year expiration so you will only need
to login once and requests using the client class will read the token from the
keyring storage.

If you call `login()` while there is a valid (non-expired) API key no action is
taken. You can replace the valid API key with `login(force=True)`.

To remove the API key from your keyring storage use the `logout()` function.

```python
from anaconda_cloud_auth import logout

logout()
```

### API requests

The BaseClient class is a subclass of [requests.Session](https://requests.readthedocs.io/en/latest/user/advanced/#session-objects).
It will automatically load the API key from the keyring on each request.
If the API key is expired it will raise a `TokenExpiredError`.

The Client class can be used for non-authenticated requests, if
the API key cannot be found and the request returns 401 or 403 error codes
the `LoginRequiredError` will be raised.

```python
from anaconda_cloud_auth.client import BaseClient

client = BaseClient()

response = client.get("/api/<endpoint>")
print(response.json())
```

BaseClient accepts the following optional arguments.

* `domain`: Domain to use for requests, defaults to `anaconda.cloud`
* `ssl_verify`: Enable SSL verification, defaults to `True`
* `api_key`: API key to use for requests, if unspecified uses token set by `anaconda login`
* `user_agent`: Defaults to `anaconda-cloud-auth/<package-version>`
* `api_version`: Requested API version, defaults to latest available from the domain
* `extra_headers`: Dictionary or JSON string of extra headers to send in requests

To create a Client class specific to your package, subclass BaseClient and set
an appropriate user-agent and API version for your needs. This is automatically done
if you use the [cookiecutter](https://github.com/anaconda/anaconda-cloud-tools/tree/main/cookiecutter)
in this repository to create a new package.

```python
from anaconda_cloud_auth.client import BaseClient
class Client(BaseClient):
    _user_agent = "anaconda-cloud-<package>/<version>"
    _api_version = "<api-version>"
```

## Panel OAuth Provider

In order to use the `anaconda_cloud` auth plugin you will need an OAuth client
ID (key) and secret. The client must be configured as follows

```text
Set scopes: offline_access, openid, email, profile
Set redirect url to http://localhost:5006
Set grant type: Authorization Code
Set response types: ID Token, Token, Code
Set access token type: JWT
Set Authentication Method: HTTP Body
```

To run the app with the anaconda_cloud auth provider you will need to set several
environment variables or command-line arguments. See the
[Panel OAuth documentation](https://panel.holoviz.org/how_to/authentication/configuration.html)
for more details

```text
PANEL_OAUTH_PROVIDER=anaconda_cloud or --oauth-provider anaconda_cloud
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

## Run the unit tests

```shell
make test
```

## Run the unit tests across isolated environments with tox

```shell
make tox
```
