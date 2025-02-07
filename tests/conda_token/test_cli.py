import pytest
import urllib3.exceptions
from packaging.version import parse

from anaconda_auth._conda import cli
from anaconda_auth._conda.repo_config import CONDA_VERSION
from anaconda_auth._conda.repo_config import CondaVersionWarning


def test_token_set_no_verify_ssl(remove_anaconda_cloud_token, secret_token, capsys):
    # real InsecureRequestWarning against real server
    with pytest.warns(urllib3.exceptions.InsecureRequestWarning):
        cli.cli(["set", "--no-ssl-verify", secret_token])


def test_token_set_no_verify_ssl_mock_server(
    remove_token, secret_token, capsys, repo_url
):
    cli.cli(["set", "--no-ssl-verify", secret_token])
    ret = cli.cli(["list"])
    assert ret == 0
    captured = capsys.readouterr()
    assert captured.out.splitlines()[-1] == repo_url + " " + secret_token


def test_token_list(remove_token, capsys, repo_url):
    ret = cli.cli(["list"])
    captured = capsys.readouterr()
    assert ret == 1
    assert captured.err.splitlines()[-1] == "No tokens have been configured for %s" % (
        repo_url,
    )


def test_token_set_invalid_channel(remove_token):
    with pytest.raises(SystemExit):
        cli.cli(["set", "secret", "--include-archive-channels", "nope"])


def test_token_set(remove_token, secret_token, capsys, repo_url):
    cli.cli(["set", secret_token])

    ret = cli.cli(["list"])
    assert ret == 0
    captured = capsys.readouterr()
    assert (
        captured.out
        == """Success! Your token was validated and Conda has been configured.
%s %s\n"""
        % (repo_url, secret_token)
    )


def test_token_set_error(remove_token, capsys, repo_url):
    ret = cli.cli(["set", "SECRET"])
    assert ret == 1
    captured = capsys.readouterr()
    # we will also capture a HTTP log for the mock server; check the last line.
    assert (
        captured.err.splitlines()[-1]
        == "The token could not be validated. Please check that you have typed it correctly."
    )

    ret = cli.cli(["list"])
    assert ret == 1
    captured = capsys.readouterr()
    assert captured.err.splitlines()[-1] == "No tokens have been configured for %s" % (
        repo_url,
    )


@pytest.mark.skipif(
    CONDA_VERSION >= parse("4.10.1"),
    reason="Signature verification will warn on old versions",
)
def test_token_set_with_signing_warn(remove_token, secret_token, capsys):
    with pytest.warns(CondaVersionWarning):
        ret = cli.cli(["set", "--enable-signature-verification", secret_token])
        assert ret == 0
