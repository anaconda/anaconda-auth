import importlib

import pytest


@pytest.fixture(autouse=True)
def reset_imports():
    yield
    importlib.invalidate_caches()


def test_import_equivalence():
    mod = importlib.import_module("anaconda_auth")
    val_1 = getattr(mod, "__version__")

    mod = importlib.import_module("anaconda_cloud_auth")
    val_2 = getattr(mod, "__version__")

    assert val_1 is val_2
