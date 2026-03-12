from __future__ import annotations

from pytest_mock import MockerFixture


class TestCheckAndConfigureEnvironments:
    def test_configures_first_matching_org(self, mocker: MockerFixture):
        from anaconda_auth.environments import check_and_configure_environments

        mocker.patch(
            "anaconda_auth.environments.fetch_org_features",
            return_value=[
                {"org": "first-org", "features": ["environments"]},
                {"org": "second-org", "features": ["environments"]},
            ],
        )
        mock_configure = mocker.patch(
            "anaconda_auth.environments.configure_conda_for_environments"
        )

        check_and_configure_environments()
        mock_configure.assert_called_once_with("first-org")

    def test_skips_when_no_environments(self, mocker: MockerFixture):
        from anaconda_auth.environments import check_and_configure_environments

        mocker.patch(
            "anaconda_auth.environments.fetch_org_features",
            return_value=[
                {"org": "my-org", "features": ["notebooks"]},
            ],
        )
        mock_configure = mocker.patch(
            "anaconda_auth.environments.configure_conda_for_environments"
        )

        check_and_configure_environments()
        mock_configure.assert_not_called()

    def test_skips_when_fetch_fails(self, mocker: MockerFixture):
        from anaconda_auth.environments import check_and_configure_environments

        mocker.patch(
            "anaconda_auth.environments.fetch_org_features",
            return_value=None,
        )
        mock_configure = mocker.patch(
            "anaconda_auth.environments.configure_conda_for_environments"
        )

        check_and_configure_environments()
        mock_configure.assert_not_called()
