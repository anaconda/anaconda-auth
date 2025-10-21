from textwrap import dedent

import pytest
from packaging.version import parse

from anaconda_auth._conda.repo_config import CONDA_VERSION
from anaconda_auth._conda.repo_config import _set_ssl_verify_false
from anaconda_auth._conda.repo_config import configure_default_channels
from anaconda_auth._conda.repo_config import enable_extra_safety_checks


def test_default_channels(condarc_path):
    final_condarc = dedent(
        """\
        default_channels:
          - https://repo.anaconda.cloud/repo/main
          - https://repo.anaconda.cloud/repo/r
          - https://repo.anaconda.cloud/repo/msys2
        """
    )
    configure_default_channels(force=True)
    assert condarc_path.read_text() == final_condarc


def test_default_channels_no_exception(condarc_path, capsys):
    """Ensure that no CondaKeyError is raised if the .condarc does not have default_channels defined."""
    configure_default_channels(force=True)

    res = capsys.readouterr()
    assert "CondaKeyError: 'default_channels'" not in res.err


def test_replace_default_channels(condarc_path):
    original_condarc = dedent(
        """\
        default_channels:
          - https://repo.anaconda.com/pkg/main
          - https://repo.anaconda.com/pkg/r
          - https://repo.anaconda.com/pkg/msys2
        """
    )
    final_condarc = dedent(
        """\
        default_channels:
          - https://repo.anaconda.cloud/repo/main
          - https://repo.anaconda.cloud/repo/r
          - https://repo.anaconda.cloud/repo/msys2
        """
    )
    condarc_path.write_text(original_condarc)
    configure_default_channels(force=True)
    assert condarc_path.read_text() == final_condarc


def test_default_channels_with_inactive(condarc_path):
    original_condarc = dedent(
        """\
        default_channels:
          - https://repo.anaconda.com/pkg/main
          - https://repo.anaconda.com/pkg/r
          - https://repo.anaconda.com/pkg/msys2
        """
    )
    final_condarc = dedent(
        """\
        default_channels:
          - https://repo.anaconda.cloud/repo/main
          - https://repo.anaconda.cloud/repo/r
          - https://repo.anaconda.cloud/repo/msys2
          - https://repo.anaconda.cloud/repo/free
          - https://repo.anaconda.cloud/repo/pro
          - https://repo.anaconda.cloud/repo/mro-archive
        """
    )
    condarc_path.write_text(original_condarc)
    configure_default_channels(
        include_archive_channels=["free", "pro", "mro-archive"], force=True
    )
    assert condarc_path.read_text() == final_condarc


def test_replace_default_channels_with_inactive(condarc_path):
    final_condarc = dedent(
        """\
        default_channels:
          - https://repo.anaconda.cloud/repo/main
          - https://repo.anaconda.cloud/repo/r
          - https://repo.anaconda.cloud/repo/msys2
          - https://repo.anaconda.cloud/repo/free
          - https://repo.anaconda.cloud/repo/pro
          - https://repo.anaconda.cloud/repo/mro-archive
        """
    )
    configure_default_channels(
        include_archive_channels=["free", "pro", "mro-archive"], force=True
    )
    assert condarc_path.read_text() == final_condarc


def test_default_channels_with_conda_forge(condarc_path):
    original_condarc = dedent(
        """\
        ssl_verify: true

        default_channels:
          - https://repo.anaconda.com/pkgs/main
        channels:
          - defaults
          - conda-forge

        channel_alias: https://conda.anaconda.org/
        """
    )

    condarc_path.write_text(original_condarc)
    configure_default_channels(force=True)
    assert condarc_path.read_text() == dedent(
        """\
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


def test_no_ssl_verify_from_true(condarc_path):
    original_condarc = dedent(
        """\
        ssl_verify: true
        """
    )
    final_condarc = dedent(
        """\
        ssl_verify: false
        """
    )
    condarc_path.write_text(original_condarc)
    _set_ssl_verify_false()
    assert condarc_path.read_text() == final_condarc


def test_no_ssl_verify_from_empty(condarc_path):
    final_condarc = dedent(
        """\
        ssl_verify: false
        """
    )
    _set_ssl_verify_false()
    assert condarc_path.read_text() == final_condarc


def test_no_ssl_verify_from_false(condarc_path):
    original_condarc = dedent(
        """\
        ssl_verify: false
        """
    )
    final_condarc = dedent(
        """\
        ssl_verify: false
        """
    )

    condarc_path.write_text(original_condarc)
    _set_ssl_verify_false()
    assert condarc_path.read_text() == final_condarc


@pytest.mark.skipif(
    CONDA_VERSION < parse("4.10.1"),
    reason="Signature verification was added in Conda 4.10.1",
)
def test_enable_package_signing(condarc_path):
    final_condarc = dedent(
        """\
        extra_safety_checks: true
        signing_metadata_url_base: https://repo.anaconda.cloud/repo
        """
    )

    enable_extra_safety_checks()
    assert condarc_path.read_text() == final_condarc
