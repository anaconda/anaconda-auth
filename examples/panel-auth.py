"""An example Panel application with Anaconda auth

Panel provides capability to enable authorization for deployed applications.
The anaconda-auth package provides the anaconda_auth plugin.

In order to use the anaconda_auth plugin you will need an OAuth client
ID (key) and secret. The client must be configured as follows

    Set scopes: offline_access, openid, email, profile
    Set redirect url to http://localhost:5006
    Set grant type: Authorization Code
    Set response types: ID Token, Token, Code
    Set access token type: JWT
    Set Authentication Method: HTTP Body

In this example the applications is only accessible after successfully creating
and logging into an Anaconda account. The access_token from the browser
is available in pn.state.access_token and can be used as an API key in requests
to Anaconda endpoints. In this example the access_token is passed to the
BaseClient in order to display user information. Note that the access_token
may only be valid for 15 minutes and while Panel will refresh pn.state.access_token
you may have to re-create your client object or request a long-lived API token
in your app.

To run the app with the anaconda_auth provider you will need to set several
environment variables or command-line arguments. See https://panel.holoviz.org/how_to/authentication/configuration.html
for the full Panel auth documentation.

PANEL_OAUTH_PROVIDER=anaconda_auth or --oauth-provider anaconda_auth
PANEL_OAUTH_KEY=<key>               or --oauth-key=<key>
PANEL_OAUTH_SECRET=<secret>         or --oauth-secret=<key>
PANEL_COOKIE_SECRET=<cookie-name>   or --cookie-secret=<value>
PANEL_OAUTH_REFRESH_TOKENS=1        or --oauth-refresh-tokens
PANEL_OAUTH_OPTIONAL=1              or --oauth-optional

panel serve <arguments> panel-auth.py --show
"""

from textwrap import dedent

import panel as pn

from anaconda_auth.client import BaseClient

if pn.state.user == "guest":
    text = dedent(
        """
        # Anaconda Application.

        This app is powered by Anaconda services.
        By clicking login you are agreeing to [Anaconda terms of service](https://www.anaconda.com/terms-of-use)
        as well as any terms or restrictions of this specific application.

        An Anaconda-powered application is a [Panel](https://panel.holoviz.org) application that utilizes
        the `AnacondaLoginHandler` to allow end-users to login using their own Anaconda account and
        optionally allow them to interact with Anaconda services.

        All application developers must register their app at Anaconda to receive an OAuth client key and secret.
        """
    )

    button = pn.widgets.Button(name="Login", button_type="primary")
    button.js_on_click(code="""window.location.href = '/login'""")
    pn.Column(text, button).servable()
else:
    button = pn.widgets.Button(name="Logout", button_type="primary")
    button.js_on_click(code="""window.location.href = '/logout'""")

    client = BaseClient(api_key=pn.state.access_token)

    text = f"# Anaconda Application\nWelcome back {client.name}!"
    pn.Column(text, button).servable()
