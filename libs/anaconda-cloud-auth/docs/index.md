# `anaconda-cloud-auth` library

## CondaAuthHandler plugin

The `anaconda-cloud-auth` library provides a `CondaAuthHandler` plugin to enable easy authenticated repository access.
This feature is currently being developed for a future release.

### Configuration

If `anaconda-cloud-auth` is installed in the `base` environment, the following will need to be done to configure access to `repo.anaconda.cloud`:

This is the current process for installing a repo token, which will be streamlined further:

* Get a new access token via the web UI
* Follow the instructions in the email that is sent, which includes a step to use `conda token set <TOKEN>`

!!! note

    The plugin currently assumes that token storage mechanism, but this will likely be replaced in the future.

Then, configure the relevant settings in `~/.condarc` like this:

```
channels:
  - https://repo.anaconda.cloud/repo/main

add_anaconda_token: false

channel_settings:
  - channel: https://repo.anaconda.cloud/repo/main
    auth: anaconda-cloud-auth
```

The key is to list the `repo.anaconda.cloud` channel associated with your token's organization, and then to assign `anaconda-cloud-auth` as the `auth:` handler for that channel.
We also need to set `add_anaconda_token: false` to ensure the legacy behavior of adding the token in the URL as a `/t/<TOKEN>` field will be overridden.
This is not strictly required, as the plugin should override that behavior but it's good for testing.
