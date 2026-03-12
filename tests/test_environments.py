from __future__ import annotations

import pytest
from pytest_mock import MockerFixture


class TestGetEnvironmentsOrgs:
    def test_returns_all_matching_orgs(self):
        from anaconda_auth.environments import get_environments_orgs

        org_features = [
            {"org": "first-org", "features": ["environments"]},
            {"org": "second-org", "features": ["community"]},
            {"org": "third-org", "features": ["environments", "community"]},
        ]
        result = get_environments_orgs(org_features)
        assert result == ["first-org", "third-org"]

    def test_returns_empty_when_no_environments(self):
        from anaconda_auth.environments import get_environments_orgs

        org_features = [
            {"org": "my-org", "features": ["notebooks"]},
        ]
        result = get_environments_orgs(org_features)
        assert result == []

    def test_returns_empty_for_empty_list(self):
        from anaconda_auth.environments import get_environments_orgs

        assert get_environments_orgs([]) == []

    def test_handles_missing_features_key(self):
        from anaconda_auth.environments import get_environments_orgs

        org_features = [{"org": "my-org"}]
        result = get_environments_orgs(org_features)
        assert result == []


class TestFetchOrgFeatures:
    def test_returns_org_features(self, mocker: MockerFixture):
        from anaconda_auth.environments import fetch_org_features

        mock_client = mocker.MagicMock()
        mock_resp = mocker.MagicMock()
        mock_resp.json.return_value = {
            "organization_features": [
                {"org": "my-org", "features": ["environments"]}
            ]
        }
        mock_client.return_value = mock_client
        mock_client.get.return_value = mock_resp
        mocker.patch("anaconda_auth.environments.BaseClient", mock_client)

        result = fetch_org_features()
        assert result == [{"org": "my-org", "features": ["environments"]}]

    def test_returns_none_on_failure(self, mocker: MockerFixture):
        from anaconda_auth.environments import fetch_org_features

        mock_client = mocker.MagicMock()
        mock_client.return_value = mock_client
        mock_client.get.side_effect = Exception("connection error")
        mocker.patch("anaconda_auth.environments.BaseClient", mock_client)

        result = fetch_org_features()
        assert result is None

    def test_returns_empty_list_when_no_org_features(self, mocker: MockerFixture):
        from anaconda_auth.environments import fetch_org_features

        mock_client = mocker.MagicMock()
        mock_resp = mocker.MagicMock()
        mock_resp.json.return_value = {}
        mock_client.return_value = mock_client
        mock_client.get.return_value = mock_resp
        mocker.patch("anaconda_auth.environments.BaseClient", mock_client)

        result = fetch_org_features()
        assert result == []