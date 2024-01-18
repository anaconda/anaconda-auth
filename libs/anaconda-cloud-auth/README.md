# anaconda-cloud-auth

A client library for Anaconda.cloud APIs to authenticate and securely store API keys.

This package provides a [requests](https://requests.readthedocs.io/en/latest/)
client class that handles loading the API key for requests made to Anaconda Cloud services.

This package provides a [Panel OAuth plugin](https://panel.holoviz.org/how_to/authentication/configuration.html)
called `anaconda_cloud`.

## Installation

```text
conda install anaconda-cloud-auth
```

## Interactive login/logout

In order to use the request client class you must first login interactively.
This can be done using the Python API or CLI (see below).

### Login API

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

#### Password-based flow (Deprecated)

WARNING: Password-based login flow will be disable in the near future.

You can login into Anaconda Cloud using username/password flow (non-browser)
with the `basic=True` keyword argument. The `login()` function will interactively
request your username and password before completing login and storing the API
key.

```python
from anaconda_cloud_auth import login

login(basic=True)
```

## Logout

To remove the API key from your keyring storage use the `logout()` function.

```python
from anaconda_cloud_auth import logout

logout()
```

## API requests

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

## CLI usage

To use `anaconda-cloud-auth` as a CLI you will need to install the
`anaconda-cloud` package. Once installed you can use the `anaconda`
CLI to login and logout of Anaconda Cloud.

```text
❯ anaconda login --help

 Usage: anaconda login [OPTIONS]

 Login to your Anaconda account.

╭─ Options ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --domain                  TEXT  [default: None]                                                                                │
│ --basic     --no-basic          Deprecated [default: no-basic]                                                                │
│ --force     --no-force          [default: no-force]                                                                            │
│ --help                          Show this message and exit.                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

## Configuration

You can configure `anaconda-cloud-auth` by setting one or more `ANACONDA_CLOUD_`
environment variables or use a `.env` file. The `.env` file must be in your
current working directory.  An example template is provided in the repo, which
contains the following options, which are the default values.

```dotenv
# Logging level
LOGGING_LEVEL="INFO"

# Base URL for all API endpoints
ANACONDA_CLOUD_API_DOMAIN="anaconda.cloud"

# Authentication settings
ANACONDA_CLOUD_AUTH_DOMAIN="id.anaconda.cloud"
ANACONDA_CLOUD_AUTH_CLIENT_ID="b4ad7f1d-c784-46b5-a9fe-106e50441f5a"
```

In addition to the variables above you can set the following

```dotenv
# API key to use for all requests, this will ignore the keyring token set by `anaconda login`
ANACONDA_CLOUD_API_KEY="<api-key>"

# Extra headers to use in all requests; must be parsable JSON format
ANACONDA_CLOUD_API_EXTRA_HEADERS='<json-parsable-dictionary>'
```

## Panel OAuth Provider

In order to use the anaconda_cloud auth plugin you will need an OAuth client
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
