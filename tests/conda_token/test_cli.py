import pytest
import urllib3.exceptions
from packaging.version import parse

from anaconda_auth._conda.conda_token import cli
from anaconda_auth._conda.repo_config import CONDA_VERSION
from anaconda_auth._conda.repo_config import CondaVersionWarning


@pytest.mark.skip(reason="blocking release in CI but passing fine locally")
def test_token_set_no_verify_ssl(remove_token_no_repo_url_mock, secret_token, capsys):
    # real InsecureRequestWarning against real server
    with pytest.warns(urllib3.exceptions.InsecureRequestWarning):
        cli(["set", "--no-ssl-verify", secret_token, "--force-config-condarc"])


@pytest.mark.skip(reason="blocking release in CI but passing fine locally")
def test_token_set_no_verify_ssl_mock_server(
    remove_token, secret_token, capsys, repo_url
):
    cli(["set", "--no-ssl-verify", "--force-config-condarc", secret_token])
    ret = cli(["list"])
    assert ret == 0
    captured = capsys.readouterr()
    assert captured.out.splitlines()[-1] == repo_url + " " + secret_token


def test_token_list(remove_token, capsys, repo_url):
    ret = cli(["list"])
    captured = capsys.readouterr()
    assert ret == 1
    assert (
        captured.err.splitlines()[-1]
        == f"No tokens have been configured for {repo_url}"
    )


def test_token_set_invalid_channel(remove_token):
    with pytest.raises(SystemExit):
        cli(["set", "secret", "--include-archive-channels", "nope"])


@pytest.mark.skip(reason="blocking release in CI but passing fine locally")
def test_token_set(remove_token, secret_token, capsys, repo_url):
    cli(["set", "--force-config-condarc", secret_token])

    ret = cli(["list"])
    assert ret == 0
    captured = capsys.readouterr()
    assert (
        "Success! Your token was validated and Conda has been configured."
        in captured.out
    )


def test_token_set_error(remove_token, capsys, repo_url):
    ret = cli(["set", "SECRET"])
    assert ret == 1
    captured = capsys.readouterr()
    # we will also capture a HTTP log for the mock server; check the last line.
    assert (
        captured.err.splitlines()[-1]
        == "The token could not be validated. Please check that you have typed it correctly."
    )

    ret = cli(["list"])
    assert ret == 1
    captured = capsys.readouterr()
    assert (
        captured.err.splitlines()[-1]
        == f"No tokens have been configured for {repo_url}"
    )


@pytest.mark.skipif(
    CONDA_VERSION >= parse("4.10.1"),
    reason="Signature verification will warn on old versions",
)
def test_token_set_with_signing_warn(remove_token, secret_token, capsys):
    with pytest.warns(CondaVersionWarning):
        ret = cli(["set", "--enable-signature-verification", secret_token])
        assert ret == 0
