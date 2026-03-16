from __future__ import annotations

import json

from pytest_mock import MockerFixture

CONDA_PATH = "/usr/bin/conda"


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


class TestInstallEnvManager:
    def test_returns_true_on_success(self, mocker: MockerFixture):
        from anaconda_auth._conda.env_logger_config import install_env_manager

        mock_proc = mocker.MagicMock(returncode=0, stderr="")
        mocker.patch(
            "anaconda_auth._conda.env_logger_config.subprocess.run",
            return_value=mock_proc,
        )
        success, error = install_env_manager(CONDA_PATH)
        assert success is True
        assert error == ""

    def test_returns_false_on_failure(self, mocker: MockerFixture):
        from anaconda_auth._conda.env_logger_config import install_env_manager

        mock_proc = mocker.MagicMock(returncode=1, stderr="error", stdout="")
        mocker.patch(
            "anaconda_auth._conda.env_logger_config.subprocess.run",
            return_value=mock_proc,
        )
        success, error = install_env_manager(CONDA_PATH)
        assert success is False
        assert error == "error"


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
