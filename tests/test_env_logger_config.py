from __future__ import annotations

import json
import subprocess

import pytest
from pytest_mock import MockerFixture

CONDA_PATH = "/usr/bin/conda"


@pytest.fixture
def mock_install_flow(mocker: MockerFixture):
    """Patch subprocess.run for install_env_manager's probe/tos/install calls.

    Call with the install-step mock proc (and optionally the probe/tos
    returncodes) to get back the patched mock_run, so the ordered
    side_effect list lives in one place.
    """

    def _mock_install_flow(mock_install_proc, probe_returncode=0, tos_returncode=0):
        probe_stdout = (
            json.dumps([{"name": "conda-anaconda-tos"}])
            if probe_returncode == 0
            else ""
        )
        side_effect = [
            mocker.MagicMock(
                returncode=probe_returncode, stdout=probe_stdout, stderr=""
            )
        ]
        if probe_returncode == 0:
            side_effect.append(mocker.MagicMock(returncode=tos_returncode, stderr=""))
        side_effect.append(mock_install_proc)
        return mocker.patch(
            "anaconda_auth._conda.env_logger_config.subprocess.run",
            side_effect=side_effect,
        )

    return _mock_install_flow


class TestIsEnvManagerInstalled:
    def test_returns_true_when_installed(self, mocker: MockerFixture):
        from anaconda_auth._conda.env_logger_config import is_env_manager_installed

        packages = [{"name": "anaconda-env-manager", "version": "0.1.0"}]
        mock_proc = mocker.MagicMock(
            returncode=0, stdout=json.dumps(packages), stderr=""
        )
        mocker.patch(
            "anaconda_auth._conda.env_logger_config.subprocess.run",
            return_value=mock_proc,
        )
        assert is_env_manager_installed(CONDA_PATH) is True

    def test_returns_false_when_not_installed(self, mocker: MockerFixture):
        from anaconda_auth._conda.env_logger_config import is_env_manager_installed

        mock_proc = mocker.MagicMock(returncode=0, stdout=json.dumps([]), stderr="")
        mocker.patch(
            "anaconda_auth._conda.env_logger_config.subprocess.run",
            return_value=mock_proc,
        )
        assert is_env_manager_installed(CONDA_PATH) is False

    def test_returns_false_on_command_failure(self, mocker: MockerFixture):
        from anaconda_auth._conda.env_logger_config import is_env_manager_installed

        mock_proc = mocker.MagicMock(returncode=1, stdout="", stderr="error")
        mocker.patch(
            "anaconda_auth._conda.env_logger_config.subprocess.run",
            return_value=mock_proc,
        )
        assert is_env_manager_installed(CONDA_PATH) is False

    def test_returns_false_on_invalid_json(self, mocker: MockerFixture):
        from anaconda_auth._conda.env_logger_config import is_env_manager_installed

        mock_proc = mocker.MagicMock(returncode=0, stdout="not json", stderr="")
        mocker.patch(
            "anaconda_auth._conda.env_logger_config.subprocess.run",
            return_value=mock_proc,
        )
        assert is_env_manager_installed(CONDA_PATH) is False

    def test_returns_false_when_different_package(self, mocker: MockerFixture):
        from anaconda_auth._conda.env_logger_config import is_env_manager_installed

        packages = [{"name": "some-other-package", "version": "1.0"}]
        mock_proc = mocker.MagicMock(
            returncode=0, stdout=json.dumps(packages), stderr=""
        )
        mocker.patch(
            "anaconda_auth._conda.env_logger_config.subprocess.run",
            return_value=mock_proc,
        )
        assert is_env_manager_installed(CONDA_PATH) is False


class TestTosPluginAvailable:
    def test_returns_true_when_available(self, mocker: MockerFixture):
        from anaconda_auth._conda.env_logger_config import _tos_plugin_available

        packages = [{"name": "conda-anaconda-tos", "version": "0.2.2"}]
        mock_proc = mocker.MagicMock(
            returncode=0, stdout=json.dumps(packages), stderr=""
        )
        mock_run = mocker.patch(
            "anaconda_auth._conda.env_logger_config.subprocess.run",
            return_value=mock_proc,
        )
        assert _tos_plugin_available(CONDA_PATH) is True

        args = mock_run.call_args[0][0]
        assert args == [
            CONDA_PATH,
            "list",
            "-n",
            "base",
            "conda-anaconda-tos",
            "--json",
        ]
        # A local metadata read only, not a live network probe.
        assert mock_run.call_args.kwargs.get("capture_output") is True

    def test_returns_false_when_not_installed(self, mocker: MockerFixture):
        from anaconda_auth._conda.env_logger_config import _tos_plugin_available

        mock_proc = mocker.MagicMock(returncode=0, stdout=json.dumps([]), stderr="")
        mocker.patch(
            "anaconda_auth._conda.env_logger_config.subprocess.run",
            return_value=mock_proc,
        )
        assert _tos_plugin_available(CONDA_PATH) is False

    def test_returns_false_on_command_failure(self, mocker: MockerFixture):
        from anaconda_auth._conda.env_logger_config import _tos_plugin_available

        mock_proc = mocker.MagicMock(returncode=1, stdout="", stderr="error")
        mocker.patch(
            "anaconda_auth._conda.env_logger_config.subprocess.run",
            return_value=mock_proc,
        )
        assert _tos_plugin_available(CONDA_PATH) is False

    def test_returns_false_on_invalid_json(self, mocker: MockerFixture):
        from anaconda_auth._conda.env_logger_config import _tos_plugin_available

        mock_proc = mocker.MagicMock(returncode=0, stdout="not json", stderr="")
        mocker.patch(
            "anaconda_auth._conda.env_logger_config.subprocess.run",
            return_value=mock_proc,
        )
        assert _tos_plugin_available(CONDA_PATH) is False

    def test_logs_debug_message_when_probe_fails(self, caplog, mocker: MockerFixture):
        """Probe failures must be logged, not silently swallowed."""
        import logging

        from anaconda_auth._conda.env_logger_config import _tos_plugin_available

        mock_proc = mocker.MagicMock(returncode=1, stdout="", stderr="CondaError")
        mocker.patch(
            "anaconda_auth._conda.env_logger_config.subprocess.run",
            return_value=mock_proc,
        )
        logger_name = "anaconda_auth._conda.env_logger_config"
        with caplog.at_level(logging.DEBUG, logger=logger_name):
            _tos_plugin_available(CONDA_PATH)

        assert any(
            "conda-anaconda-tos probe failed" in record.message
            for record in caplog.records
        )
        assert any("CondaError" in record.message for record in caplog.records)


class TestInstallEnvManager:
    def test_returns_true_on_success(self, mocker: MockerFixture, mock_install_flow):
        from anaconda_auth._conda.env_logger_config import install_env_manager

        mock_install_proc = mocker.MagicMock(returncode=0, stdout="{}", stderr="")
        mock_run = mock_install_flow(mock_install_proc)
        success, error = install_env_manager(CONDA_PATH)
        assert success is True
        assert error == ""

        tos_args = mock_run.call_args_list[1][0][0]
        assert "tos" in tos_args
        assert "interactive" in tos_args
        # Prompts must inherit stdout; only stderr is captured (and logged).
        assert "capture_output" not in mock_run.call_args_list[1].kwargs
        assert mock_run.call_args_list[1].kwargs.get("stderr") == subprocess.PIPE

        install_args = mock_run.call_args_list[2][0][0]
        assert "--yes" in install_args
        assert "--json" in install_args
        assert mock_run.call_args_list[2].kwargs.get("capture_output") is True

    def test_skips_interactive_step_when_plugin_not_available(
        self, mocker: MockerFixture, mock_install_flow
    ):
        from anaconda_auth._conda.env_logger_config import install_env_manager

        mock_install_proc = mocker.MagicMock(returncode=0, stdout="{}", stderr="")
        mock_run = mock_install_flow(mock_install_proc, probe_returncode=2)
        success, error = install_env_manager(CONDA_PATH)
        assert success is True
        assert error == ""
        # No "tos interactive" call.
        assert mock_run.call_count == 2

    def test_proceeds_when_tos_interactive_fails(
        self, mocker: MockerFixture, mock_install_flow
    ):
        """A ToS step failure must never block the install."""
        from anaconda_auth._conda.env_logger_config import install_env_manager

        mock_install_proc = mocker.MagicMock(returncode=0, stdout="{}", stderr="")
        mock_install_flow(mock_install_proc, tos_returncode=1)
        success, error = install_env_manager(CONDA_PATH)
        assert success is True

    def test_logs_instead_of_printing_transient_tos_interactive_failure(
        self, caplog, mocker: MockerFixture, mock_install_flow
    ):
        """Transient ToS step stderr (e.g. a network blip) must be logged,
        not printed, so it doesn't look like a broken install when the
        subsequent conda install actually succeeds."""
        import logging

        from anaconda_auth._conda.env_logger_config import install_env_manager

        mock_install_proc = mocker.MagicMock(returncode=0, stdout="{}", stderr="")
        mocker.patch(
            "anaconda_auth._conda.env_logger_config.subprocess.run",
            side_effect=[
                mocker.MagicMock(
                    returncode=0, stdout=json.dumps([{"name": "conda-anaconda-tos"}])
                ),
                mocker.MagicMock(returncode=1, stderr="CondaHTTPError: timed out"),
                mock_install_proc,
            ],
        )
        logger_name = "anaconda_auth._conda.env_logger_config"
        with caplog.at_level(logging.DEBUG, logger=logger_name):
            success, _ = install_env_manager(CONDA_PATH)

        assert success is True
        assert any(
            "CondaHTTPError: timed out" in record.message for record in caplog.records
        )

    def test_fails_fast_on_confirmed_tos_rejection(
        self, mocker: MockerFixture, mock_install_flow
    ):
        """A confirmed rejection from `conda tos interactive` must fail
        immediately, without ever attempting (or announcing) the install—
        `conda install` would only fail again for the same reason."""
        from anaconda_auth._conda.env_logger_config import install_env_manager

        rejection_text = (
            "CondaToSRejectedError: Terms of Service has been rejected for the "
            "following channels. Please remove or accept them before proceeding:\n"
            "    - https://repo.anaconda.com/pkgs/main"
        )
        mock_run = mocker.patch(
            "anaconda_auth._conda.env_logger_config.subprocess.run",
            side_effect=[
                mocker.MagicMock(
                    returncode=0, stdout=json.dumps([{"name": "conda-anaconda-tos"}])
                ),
                mocker.MagicMock(returncode=1, stderr=rejection_text),
            ],
        )
        printed = []
        mocker.patch(
            "anaconda_auth._conda.env_logger_config.console.print",
            side_effect=lambda *a, **k: printed.append(a[0] if a else ""),
        )

        success, error = install_env_manager(CONDA_PATH)

        assert success is False
        assert "Terms of Service has been rejected" in error
        assert "CondaToSRejectedError" not in error
        # conda install must never be attempted, nor announced.
        assert mock_run.call_count == 2
        assert printed == ["Checking channel Terms of Service..."]

    def test_returns_false_on_failure(self, mocker: MockerFixture, mock_install_flow):
        from anaconda_auth._conda.env_logger_config import install_env_manager

        mock_install_proc = mocker.MagicMock(returncode=1, stdout="{}", stderr="")
        mock_install_flow(mock_install_proc)
        success, error = install_env_manager(CONDA_PATH)
        assert success is False
        assert error == "conda install exited with code 1."

    def test_includes_json_error_message_on_failure(
        self, mocker: MockerFixture, mock_install_flow
    ):
        from anaconda_auth._conda.env_logger_config import install_env_manager

        mock_install_proc = mocker.MagicMock(
            returncode=1,
            stdout='{"message": "PackagesNotFoundError: nope"}',
            stderr="",
        )
        mock_install_flow(mock_install_proc)
        success, error = install_env_manager(CONDA_PATH)
        assert success is False
        assert "PackagesNotFoundError: nope" in error

    def test_falls_back_to_stderr_when_stdout_has_no_json_message(
        self, mocker: MockerFixture, mock_install_flow
    ):
        """Falls back to stderr when stdout has no usable JSON message."""
        from anaconda_auth._conda.env_logger_config import install_env_manager

        mock_install_proc = mocker.MagicMock(
            returncode=1,
            stdout="",
            stderr="CondaHTTPError: connection failed",
        )
        mock_install_flow(mock_install_proc)
        success, error = install_env_manager(CONDA_PATH)
        assert success is False
        assert "CondaHTTPError: connection failed" in error

    def test_extracts_json_error_message_from_stderr_on_tos_rejection(
        self, mocker: MockerFixture, mock_install_flow
    ):
        """conda writes the --json error payload to stderr (not stdout) when
        it's raised from a pre-command hook, e.g. a rejected ToS. The clean
        message should still be extracted rather than falling back to the
        raw JSON blob."""
        from anaconda_auth._conda.env_logger_config import install_env_manager

        mock_install_proc = mocker.MagicMock(
            returncode=1,
            stdout="",
            stderr=json.dumps(
                {
                    "message": "Terms of Service has been rejected for the following channels: defaults",
                    "exception_name": "CondaToSRejectedError",
                }
            ),
        )
        mock_install_flow(mock_install_proc)
        success, error = install_env_manager(CONDA_PATH)
        assert success is False
        assert (
            "Terms of Service has been rejected for the following channels: defaults"
            in error
        )
        assert "exception_name" not in error

    def test_handles_none_stdout_without_raising(
        self, mocker: MockerFixture, mock_install_flow
    ):
        """json.loads(None) raises TypeError; must be caught, not raised."""
        from anaconda_auth._conda.env_logger_config import install_env_manager

        mock_install_proc = mocker.MagicMock(
            returncode=1, stdout=None, stderr="unexpected crash"
        )
        mock_install_flow(mock_install_proc)
        success, error = install_env_manager(CONDA_PATH)
        assert success is False
        assert "unexpected crash" in error

    def test_pins_version_when_configured(
        self, monkeypatch, mocker: MockerFixture, mock_install_flow
    ):
        monkeypatch.setenv("ANACONDA_AUTH_ENV_MANAGER_VERSION", "1.2.3")

        from anaconda_auth._conda.env_logger_config import install_env_manager

        mock_install_proc = mocker.MagicMock(returncode=0, stdout="{}", stderr="")
        mock_run = mock_install_flow(mock_install_proc)
        install_env_manager(CONDA_PATH)

        args = mock_run.call_args_list[2][0][0]
        assert "anaconda-cloud::anaconda-env-manager=1.2.3" in args

    def test_uses_custom_channel(
        self, monkeypatch, mocker: MockerFixture, mock_install_flow
    ):
        monkeypatch.setenv("ANACONDA_AUTH_ENV_MANAGER_CHANNEL", "my-channel")

        from anaconda_auth._conda.env_logger_config import install_env_manager

        mock_install_proc = mocker.MagicMock(returncode=0, stdout="{}", stderr="")
        mock_run = mock_install_flow(mock_install_proc)
        install_env_manager(CONDA_PATH)

        install_args = mock_run.call_args_list[2][0][0]
        assert "my-channel::anaconda-env-manager" in install_args

    def test_uses_custom_package_name(
        self, monkeypatch, mocker: MockerFixture, mock_install_flow
    ):
        monkeypatch.setenv("ANACONDA_AUTH_ENV_MANAGER_PACKAGE", "custom-pkg")

        from anaconda_auth._conda.env_logger_config import install_env_manager

        mock_install_proc = mocker.MagicMock(returncode=0, stdout="{}", stderr="")
        mock_run = mock_install_flow(mock_install_proc)
        install_env_manager(CONDA_PATH)

        args = mock_run.call_args_list[2][0][0]
        assert "anaconda-cloud::custom-pkg" in args


class TestRegisterOrg:
    def test_returns_true_on_success(self, mocker: MockerFixture):
        from anaconda_auth._conda.env_logger_config import register_org

        mock_proc = mocker.MagicMock(returncode=0)
        mocker.patch(
            "anaconda_auth._conda.env_logger_config.subprocess.run",
            return_value=mock_proc,
        )
        assert register_org(CONDA_PATH) is True

    def test_returns_false_on_failure(self, mocker: MockerFixture):
        from anaconda_auth._conda.env_logger_config import register_org

        mock_proc = mocker.MagicMock(returncode=1)
        mocker.patch(
            "anaconda_auth._conda.env_logger_config.subprocess.run",
            return_value=mock_proc,
        )
        assert register_org(CONDA_PATH) is False
