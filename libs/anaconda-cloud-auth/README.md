# anaconda-cloud-auth

A client auth library for Anaconda.cloud APIs.

## Configuration

You can configure `anaconda-cloud-auth` with a `.env` file.
An example template is provided in the repo, which contains the following options:

```dotenv
# Logging level
LOGGING_LEVEL="INFO"

# Base URL for all API endpoints
BASE_URL="https://nucleus-latest.anacondaconnect.com"

# Oauth credentials/settings for the legacy IAM service
IAM_AUTH_DOMAIN="nucleus-latest.anacondaconnect.com/api/iam"
IAM_AUTH_ENDPOINT="https://nucleus-latest.anacondaconnect.com/authorize"
IAM_CLIENT_ID="cloud-cli-test-4"
IAM_CLIENT_SECRET="TPm0c0bdMDy2ngivuHIB95Hvurv999x9smdLxv2EmpKo30kS6ku3wGx183dmgcuc"

# Oauth credentials/settings for the new Ory IAM service
ORY_AUTH_DOMAIN="dev.id.anaconda.cloud"
ORY_CLIENT_ID="83d245e3-6312-4f44-9298-1f5b32a13769"
```

If you do not specify the `.env` file, the production configuration should be the default.
Please file an issue if you see any errors.

## Simple CLI usage

Several login flows are implemented, and different flows are available in dev/prod until the Ory migration is completed.

### Login

#### Browser-based flow (legacy IAM, dev-only)

You can login from your terminal using the legacy IAM account in dev only. You must provide `IAM_CLIENT_ID` and `IAM_CLIENT_SECRET`:

```shell
acli auth login
```

#### Browser-based flow (Ory, dev-only)

The Ory login flow only works in dev.
It should work in prod as well, but currently there is not an oauth2 client registered in prod.

```shell
acli auth login --ory
```

#### Password-based flow (legacy IAM, dev & prod)

If you want to authenticate with prod, you must currently use a password-based flow that will prompt you for email & password until your user is migrated into Ory:

```shell
acli auth login --simple
```

### Test your Credentials by printing your info

The response from the `/api/account` endpoint will be printed with the following, which will confirm you are authenticated:

```shell
acli auth info
```

### Make a generic request from the command line

You can make something like a curl request via the CLI, which will use your authorization token by default and handle token refresh:

```shell
acli request --method GET --no-auth --debug --json '{"key": "value"}' --token "override-bearer-token" "/api/account"
```

All the options above are optional.
If the URL starts with a `/`, the BASE_URL will be prepended.

If you include the `--debug` flag, the headers, response status code, response headers, and response data will be printed.
If not, only the JSON response will be printed.

## Simple library usage

To login (one time), use:

```python
from anaconda_cloud_auth import login

login()
```

To make authenticated API requests, use the `Client` class.
For example, to print your user credentials, do:

```python
from anaconda_cloud_auth import Client

client = Client()
response = client.get("/api/account")
print(response.json())
```

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
