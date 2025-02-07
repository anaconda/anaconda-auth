from contextlib import contextmanager
from tempfile import NamedTemporaryFile

import pytest
from conda.base.context import reset_context
from conda.gateways.disk.delete import rm_rf
from packaging.version import parse

from anaconda_auth._conda.repo_config import CONDA_VERSION
from anaconda_auth._conda.repo_config import _set_ssl_verify_false
from anaconda_auth._conda.repo_config import can_restore_free_channel
from anaconda_auth._conda.repo_config import configure_default_channels
from anaconda_auth._conda.repo_config import enable_extra_safety_checks


@contextmanager
def make_temp_condarc(value=None):
    try:
        tempfile = NamedTemporaryFile(suffix=".yml", delete=False)
        tempfile.close()
        temp_path = tempfile.name
        if value:
            with open(temp_path, "w") as f:
                f.write(value)
        reset_context([temp_path])
        yield temp_path
    finally:
        rm_rf(temp_path)


def _read_test_condarc(rc):
    with open(rc) as f:
        return f.read()


def test_default_channels():
    empty_condarc = "\n"
    final_condarc = """\
default_channels:
  - https://repo.anaconda.cloud/repo/main
  - https://repo.anaconda.cloud/repo/r
  - https://repo.anaconda.cloud/repo/msys2
"""
    if can_restore_free_channel():
        final_condarc = "restore_free_channel: false\n" + final_condarc

    with make_temp_condarc(empty_condarc) as rc:
        configure_default_channels(condarc_file=rc)
        assert _read_test_condarc(rc) == final_condarc


def test_replace_default_channels():
    original_condarc = """\
default_channels:
  - https://repo.anaconda.com/pkg/main
  - https://repo.anaconda.com/pkg/r
  - https://repo.anaconda.com/pkg/msys2
"""
    final_condarc = """\
default_channels:
  - https://repo.anaconda.cloud/repo/main
  - https://repo.anaconda.cloud/repo/r
  - https://repo.anaconda.cloud/repo/msys2
"""
    if can_restore_free_channel():
        final_condarc = "restore_free_channel: false\n" + final_condarc

    with make_temp_condarc(original_condarc) as rc:
        configure_default_channels(condarc_file=rc)
        assert _read_test_condarc(rc) == final_condarc


def test_default_channels_with_inactive():
    original_condarc = """\
default_channels:
  - https://repo.anaconda.com/pkg/main
  - https://repo.anaconda.com/pkg/r
  - https://repo.anaconda.com/pkg/msys2
"""
    final_condarc = """\
default_channels:
  - https://repo.anaconda.cloud/repo/main
  - https://repo.anaconda.cloud/repo/r
  - https://repo.anaconda.cloud/repo/msys2
  - https://repo.anaconda.cloud/repo/free
  - https://repo.anaconda.cloud/repo/pro
  - https://repo.anaconda.cloud/repo/mro-archive
"""
    if can_restore_free_channel():
        final_condarc = "restore_free_channel: false\n" + final_condarc

    with make_temp_condarc(original_condarc) as rc:
        configure_default_channels(
            condarc_file=rc, include_archive_channels=["free", "pro", "mro-archive"]
        )
        assert _read_test_condarc(rc) == final_condarc


def test_replace_default_channels_with_inactive():
    empty_condarc = "\n"
    final_condarc = """\
default_channels:
  - https://repo.anaconda.cloud/repo/main
  - https://repo.anaconda.cloud/repo/r
  - https://repo.anaconda.cloud/repo/msys2
  - https://repo.anaconda.cloud/repo/free
  - https://repo.anaconda.cloud/repo/pro
  - https://repo.anaconda.cloud/repo/mro-archive
"""
    if can_restore_free_channel():
        final_condarc = "restore_free_channel: false\n" + final_condarc

    with make_temp_condarc(empty_condarc) as rc:
        configure_default_channels(
            condarc_file=rc, include_archive_channels=["free", "pro", "mro-archive"]
        )
        assert _read_test_condarc(rc) == final_condarc


def test_default_channels_with_conda_forge():
    if can_restore_free_channel():
        original_condarc = """\
ssl_verify: true
restore_free_channel: true

default_channels:
  - https://repo.anaconda.com/pkgs/main
channels:
  - defaults
  - conda-forge

channel_alias: https://conda.anaconda.org/
"""

        with make_temp_condarc(original_condarc) as rc:
            configure_default_channels(condarc_file=rc)
            assert (
                _read_test_condarc(rc)
                == """\
ssl_verify: true
restore_free_channel: false

channels:
  - defaults
  - conda-forge

channel_alias: https://conda.anaconda.org/
default_channels:
  - https://repo.anaconda.cloud/repo/main
  - https://repo.anaconda.cloud/repo/r
  - https://repo.anaconda.cloud/repo/msys2
"""
            )
    else:
        original_condarc = """\
ssl_verify: true

default_channels:
  - https://repo.anaconda.com/pkgs/main
channels:
  - defaults
  - conda-forge

channel_alias: https://conda.anaconda.org/
"""

        with make_temp_condarc(original_condarc) as rc:
            configure_default_channels(condarc_file=rc)
            assert (
                _read_test_condarc(rc)
                == """\
ssl_verify: true

channels:
  - defaults
  - conda-forge

channel_alias: https://conda.anaconda.org/
default_channels:
  - https://repo.anaconda.cloud/repo/main
  - https://repo.anaconda.cloud/repo/r
  - https://repo.anaconda.cloud/repo/msys2
"""
            )


def test_no_ssl_verify_from_true():
    original_condarc = """
ssl_verify: true
"""
    final_condarc = """\
ssl_verify: false
"""

    with make_temp_condarc(original_condarc) as rc:
        _set_ssl_verify_false(condarc_file=rc)
        assert _read_test_condarc(rc) == final_condarc


def test_no_ssl_verify_from_empty():
    original_condarc = "\n"
    final_condarc = """\
ssl_verify: false
"""

    with make_temp_condarc(original_condarc) as rc:
        _set_ssl_verify_false(condarc_file=rc)
        assert _read_test_condarc(rc) == final_condarc


def test_no_ssl_verify_from_false():
    original_condarc = """
ssl_verify: false
"""
    final_condarc = """\
ssl_verify: false
"""

    with make_temp_condarc(original_condarc) as rc:
        _set_ssl_verify_false(condarc_file=rc)
        assert _read_test_condarc(rc) == final_condarc


@pytest.mark.skipif(
    CONDA_VERSION < parse("4.10.1"),
    reason="Signature verification was added in Conda 4.10.1",
)
def test_enable_package_signing():
    empty_condarc = ""

    final_condarc = """extra_safety_checks: true
signing_metadata_url_base: https://repo.anaconda.cloud/repo
"""

    with make_temp_condarc(empty_condarc) as rc:
        enable_extra_safety_checks(condarc_file=rc)
        assert _read_test_condarc(rc) == final_condarc
