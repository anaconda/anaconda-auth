import importlib

import pytest

# A list of all public imports, relative to the package name
PUBLIC_IMPORTS = [
    "__version__",
    "login",
    "logout",
    "client_factory",
    "actions._do_auth_flow",
    "actions.get_api_key",
    "actions.is_logged_in",
    "actions.login",
    "actions.logout",
    "actions.make_auth_code_request_url",
    "actions.refresh_access_token",
    "actions.request_access_token",
    "client.BaseClient",
    "client.BearerAuth",
    "client.client_factory",
    "client.login_required",
    # TODO: figure out what to do with this import
    # "config.AnacondaCloudConfig",
    "exceptions.AuthenticationError",
    "exceptions.InvalidTokenError",
    "exceptions.TokenNotFoundError",
    "exceptions.LoginRequiredError",
    "exceptions.TokenExpiredError",
    "handlers.capture_auth_code",
    "handlers.shutdown_all_servers",
    "token.TokenInfo",
]


@pytest.fixture(autouse=True)
def reset_imports():
    yield
    importlib.invalidate_caches()


@pytest.mark.parametrize(
    "rel_attr_path",
    PUBLIC_IMPORTS,
)
def test_import_aliases(rel_attr_path):
    """Given a relative nested import, ensure it's the same for both anaconda_auth and anaconda_cloud_auth."""
    sub_mod_path, _, attr_name = rel_attr_path.rpartition(".")

    mod_path = "anaconda_cloud_auth" + (f".{sub_mod_path}" if sub_mod_path else "")
    mod = importlib.import_module(mod_path)
    val_1 = getattr(mod, attr_name)

    mod_path = "anaconda_auth" + (f".{sub_mod_path}" if sub_mod_path else "")
    mod = importlib.import_module(mod_path)
    val_2 = getattr(mod, attr_name)

    assert val_1 is val_2


@pytest.mark.parametrize(
    "rel_attr_path",
    PUBLIC_IMPORTS,
)
def test_deprecation_warning(rel_attr_path):
    sub_mod_path, _, attr_name = rel_attr_path.rpartition(".")

    mod_path = "anaconda_cloud_auth" + (f".{sub_mod_path}" if sub_mod_path else "")

    mod = importlib.import_module(mod_path)
    with pytest.deprecated_call():
        importlib.reload(mod)
