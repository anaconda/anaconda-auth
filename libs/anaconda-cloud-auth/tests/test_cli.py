from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
from typing import Callable

import pytest
from anaconda_cloud_cli.cli import app
from mypy_extensions import VarArg
from typer.testing import CliRunner
from typer.testing import Result

if TYPE_CHECKING:
    from _pytest.monkeypatch import MonkeyPatch

CLIInvoker = Callable[[VarArg(str)], Result]


@pytest.fixture()
def invoke_cli(tmp_path: Path, monkeypatch: MonkeyPatch) -> CLIInvoker:
    """Returns a function, which can be used to call the CLI from within a temporary directory."""
    runner = CliRunner()

    monkeypatch.chdir(tmp_path)

    def f(*args: str) -> Result:
        return runner.invoke(app, args)

    return f


def test_auth_subcommand_help(invoke_cli: CLIInvoker) -> None:
    """Auth is available as a subcommand of the core CLI app."""
    result = invoke_cli("auth", "--help")
    assert result.exit_code == 0
