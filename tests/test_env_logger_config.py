from __future__ import annotations

import json

from pytest_mock import MockerFixture


class TestIsEnvManagerInstalled:
    def test_returns_true_when_installed(self, mocker: MockerFixture):
        from anaconda_auth._conda.env_logger_config import is_env_manager_installed

        packages = [{"name": "anaconda-env-manager", "version": "0.1.0"}]
        mocker.patch(
            "anaconda_auth._conda.env_logger_config.run_command",
            return_value=(json.dumps(packages), "", 0),
        )
        assert is_env_manager_installed() is True

    def test_returns_false_when_not_installed(self, mocker: MockerFixture):
        from anaconda_auth._conda.env_logger_config import is_env_manager_installed

        mocker.patch(
            "anaconda_auth._conda.env_logger_config.run_command",
            return_value=(json.dumps([]), "", 0),
        )
        assert is_env_manager_installed() is False

    def test_returns_false_on_command_failure(self, mocker: MockerFixture):
        from anaconda_auth._conda.env_logger_config import is_env_manager_installed

        mocker.patch(
            "anaconda_auth._conda.env_logger_config.run_command",
            return_value=("", "error", 1),
        )
        assert is_env_manager_installed() is False

    def test_returns_false_on_invalid_json(self, mocker: MockerFixture):
        from anaconda_auth._conda.env_logger_config import is_env_manager_installed

        mocker.patch(
            "anaconda_auth._conda.env_logger_config.run_command",
            return_value=("not json", "", 0),
        )
        assert is_env_manager_installed() is False

    def test_returns_false_when_different_package(self, mocker: MockerFixture):
        from anaconda_auth._conda.env_logger_config import is_env_manager_installed

        packages = [{"name": "some-other-package", "version": "1.0"}]
        mocker.patch(
            "anaconda_auth._conda.env_logger_config.run_command",
            return_value=(json.dumps(packages), "", 0),
        )
        assert is_env_manager_installed() is False


class TestInstallEnvManager:
    def test_returns_true_on_success(self, mocker: MockerFixture):
        from anaconda_auth._conda.env_logger_config import install_env_manager

        mock_proc = mocker.MagicMock(returncode=0, stderr="")
        mocker.patch(
            "anaconda_auth._conda.env_logger_config.subprocess.run",
            return_value=mock_proc,
        )
        success, error = install_env_manager()
        assert success is True
        assert error == ""

    def test_returns_false_on_failure(self, mocker: MockerFixture):
        from anaconda_auth._conda.env_logger_config import install_env_manager

        mock_proc = mocker.MagicMock(returncode=1, stderr="error", stdout="")
        mocker.patch(
            "anaconda_auth._conda.env_logger_config.subprocess.run",
            return_value=mock_proc,
        )
        success, error = install_env_manager()
        assert success is False
        assert error == "error"


class TestRegisterOrg:
    def test_returns_true_on_success(self, mocker: MockerFixture):
        from anaconda_auth._conda.env_logger_config import register_org

        mock_proc = mocker.MagicMock(returncode=0, stderr="")
        mocker.patch(
            "anaconda_auth._conda.env_logger_config.subprocess.run",
            return_value=mock_proc,
        )
        assert register_org() is True

    def test_returns_false_on_failure(self, mocker: MockerFixture):
        from anaconda_auth._conda.env_logger_config import register_org

        mock_proc = mocker.MagicMock(returncode=1, stderr="error")
        mocker.patch(
            "anaconda_auth._conda.env_logger_config.subprocess.run",
            return_value=mock_proc,
        )
        assert register_org() is False
