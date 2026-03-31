from __future__ import annotations

import pytest
from pytest_mock import MockerFixture

from anaconda_auth.env_logger import fetch_org_features
from anaconda_auth.env_logger import get_orgs_with_env_logger
from anaconda_auth.env_logger import check_client_token_status


class TestGetOrgsWithEnvLogger:
    def test_returns_all_matching_orgs(self):
        org_features = [
            {"org": "first-org", "features": ["environments"]},
            {"org": "second-org", "features": ["community"]},
            {"org": "third-org", "features": ["environments", "community"]},
        ]
        result = get_orgs_with_env_logger(org_features)
        assert result == ["first-org", "third-org"]

    def test_returns_empty_when_no_environments(self):
        org_features = [
            {"org": "my-org", "features": ["notebooks"]},
        ]
        result = get_orgs_with_env_logger(org_features)
        assert result == []

    def test_returns_empty_for_empty_list(self):
        assert get_orgs_with_env_logger([]) == []

    def test_handles_missing_features_key(self):
        org_features = [{"org": "my-org"}]
        result = get_orgs_with_env_logger(org_features)
        assert result == []


class TestFetchOrgFeatures:
    def test_returns_org_features(self, mocker: MockerFixture):
        mock_client = mocker.MagicMock()
        mock_resp = mocker.MagicMock()
        mock_resp.json.return_value = {
            "organization_features": [{"org": "my-org", "features": ["environments"]}]
        }
        mock_client.return_value = mock_client
        mock_client.get.return_value = mock_resp
        mocker.patch("anaconda_auth.env_logger.BaseClient", mock_client)

        result = fetch_org_features()
        assert result == [{"org": "my-org", "features": ["environments"]}]

    @pytest.mark.parametrize("ssl_verify", [True, False, None])
    def test_returns_org_features_supports_ssl_verify(
        self, ssl_verify: bool | None, mocker: MockerFixture
    ):

        mock_client = mocker.MagicMock()
        mock_resp = mocker.MagicMock()
        mock_resp.json.return_value = {
            "organization_features": [{"org": "my-org", "features": ["environments"]}]
        }
        mock_client.return_value = mock_client
        mock_client.get.return_value = mock_resp
        MockedBaseClient = mocker.patch(
            "anaconda_auth.env_logger.BaseClient", mock_client
        )

        result = fetch_org_features(ssl_verify=ssl_verify)
        assert (
            MockedBaseClient.call_args.kwargs == {}
            if ssl_verify is None
            else {"ssl_verify": ssl_verify}
        )
        assert result == [{"org": "my-org", "features": ["environments"]}]

    def test_returns_none_on_failure(self, mocker: MockerFixture):
        mock_client = mocker.MagicMock()
        mock_client.return_value = mock_client
        mock_client.get.side_effect = Exception("connection error")
        mocker.patch("anaconda_auth.env_logger.BaseClient", mock_client)

        result = fetch_org_features()
        assert result is None

    def test_returns_empty_list_when_no_org_features(self, mocker: MockerFixture):
        from anaconda_auth.env_logger import fetch_org_features

        mock_client = mocker.MagicMock()
        mock_resp = mocker.MagicMock()
        mock_resp.json.return_value = {}
        mock_client.return_value = mock_client
        mock_client.get.return_value = mock_resp
        mocker.patch("anaconda_auth.env_logger.BaseClient", mock_client)

        result = fetch_org_features()
        assert result == []


class TestCheckClientTokenStatus:
    def test_returns_true_when_registered(self, mocker: MockerFixture):

        mock_client = mocker.MagicMock()
        mock_resp = mocker.MagicMock()
        mock_resp.status_code = 200
        mock_client.return_value = mock_client
        mock_client.get.return_value = mock_resp
        mocker.patch("anaconda_auth.env_logger.BaseClient", mock_client)

        assert check_client_token_status("test-token") is True
        mock_client.get.assert_called_once_with(
            "/api/environments/client-token-status",
            params={"client_token": "test-token"},
        )

    def test_returns_false_when_not_registered(self, mocker: MockerFixture):

        mock_client = mocker.MagicMock()
        mock_resp = mocker.MagicMock()
        mock_resp.status_code = 404
        mock_client.return_value = mock_client
        mock_client.get.return_value = mock_resp
        mocker.patch("anaconda_auth.env_logger.BaseClient", mock_client)

        assert check_client_token_status("test-token") is False

    def test_returns_false_on_exception(self, mocker: MockerFixture):

        mock_client = mocker.MagicMock()
        mock_client.return_value = mock_client
        mock_client.get.side_effect = Exception("connection error")
        mocker.patch("anaconda_auth.env_logger.BaseClient", mock_client)

        assert check_client_token_status("test-token") is False
