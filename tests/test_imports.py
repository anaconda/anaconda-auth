import importlib

import pytest


@pytest.fixture(autouse=True)
def reset_imports():
    yield
    importlib.invalidate_caches()


@pytest.mark.parametrize(
    "rel_attr_path",
    [
        "__version__",
        "login",
        "logout",
        "client_factory",
    ],
)
def test_import_equivalence(rel_attr_path):
    sub_mod_path, _, attr_name = rel_attr_path.rpartition(".")

    mod_path = "anaconda_auth" + (f".{sub_mod_path}" if sub_mod_path else "")
    mod = importlib.import_module(mod_path)
    val_1 = getattr(mod, attr_name)

    mod_path = "anaconda_cloud_auth" + (f".{sub_mod_path}" if sub_mod_path else "")
    mod = importlib.import_module(mod_path)
    val_2 = getattr(mod, attr_name)

    assert val_1 is val_2
