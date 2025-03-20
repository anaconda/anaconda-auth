from pathlib import Path

import keyring
import pytest
from keyring.errors import PasswordDeleteError
from pytest import MonkeyPatch
from pytest_mock import MockerFixture

import anaconda_auth.token
from anaconda_auth.actions import logout
from anaconda_auth.config import AnacondaAuthConfig
from anaconda_auth.config import AnacondaCloudConfig
from anaconda_auth.token import TokenExpiredError
from anaconda_auth.token import TokenInfo
from anaconda_auth.token import TokenNotFoundError


def test_expired_token_error(outdated_token_info: TokenInfo) -> None:
    with pytest.raises(TokenExpiredError):
        _ = outdated_token_info.get_access_token()


def test_token_not_found() -> None:
    config = AnacondaAuthConfig()

    with pytest.raises(TokenNotFoundError):
        _ = TokenInfo.load(config.domain)

    with pytest.raises(TokenNotFoundError):
        _ = TokenInfo(domain=config.domain).get_access_token()


def test_logout_multiple_okay(mocker: MockerFixture) -> None:
    """We can logout multiple times and no exception is raised."""
    import keyring

    delete_spy = mocker.spy(keyring, "delete_password")

    config = AnacondaAuthConfig(domain="test")
    token_info = TokenInfo(api_key="key", domain=config.domain)
    token_info.save()

    for _ in range(2):
        logout(config)

    delete_spy.assert_called_once()


def test_preferred_token_storage(monkeypatch: MonkeyPatch) -> None:
    import keyring.backend

    backends = {k.name: k for k in keyring.backend.get_all_keyring()}

    assert "token AnacondaKeyring" in backends
    assert backends["token AnacondaKeyring"].priority == 11.0
    assert (
        backends["token AnacondaKeyring"].priority
        > backends["chainer ChainerBackend"].priority
    )

    monkeypatch.setenv("ANACONDA_AUTH_PREFERRED_TOKEN_STORAGE", "system")
    backends = {k.name: k for k in keyring.backend.get_all_keyring()}

    assert "token AnacondaKeyring" in backends
    assert backends["token AnacondaKeyring"].priority == 0.2
    assert (
        backends["token AnacondaKeyring"].priority
        < backends["chainer ChainerBackend"].priority
    )


def test_anaconda_keyring_save_delete(tmp_path: Path) -> None:
    from anaconda_auth.token import AnacondaKeyring

    fn = tmp_path / "keyring"
    AnacondaKeyring.keyring_path = fn
    assert AnacondaKeyring.viable

    anaconda_keyring = AnacondaKeyring()

    assert anaconda_keyring.get_password("s", "u") is None

    with pytest.raises(PasswordDeleteError):
        anaconda_keyring.delete_password("s", "u")

    anaconda_keyring.set_password("s", "u", "p")
    assert anaconda_keyring.keyring_path.exists()
    assert anaconda_keyring.keyring_path.read_text() == '{"s": {"u": "p"}}'

    anaconda_keyring.set_password("s", "u2", "p")
    assert anaconda_keyring.keyring_path.read_text() == '{"s": {"u": "p", "u2": "p"}}'

    assert anaconda_keyring.viable

    assert anaconda_keyring.get_password("s", "u") == "p"
    assert anaconda_keyring.get_password("s", "u3") is None

    anaconda_keyring.delete_password("s", "u")
    assert anaconda_keyring.keyring_path.read_text() == '{"s": {"u2": "p"}}'

    anaconda_keyring.set_password("s2", "u", "p")
    assert (
        anaconda_keyring.keyring_path.read_text()
        == '{"s": {"u2": "p"}, "s2": {"u": "p"}}'
    )

    anaconda_keyring.delete_password("s", "u2")
    assert anaconda_keyring.keyring_path.read_text() == '{"s": {}, "s2": {"u": "p"}}'

    with pytest.raises(PasswordDeleteError):
        anaconda_keyring.delete_password("s", "u2")

    assert anaconda_keyring.get_password("s3", "u4") is None


def test_anaconda_keyring_empty(tmp_path: Path) -> None:
    fn = tmp_path / "keyring"
    fn.touch()
    assert fn.exists()

    from anaconda_auth.token import AnacondaKeyring

    AnacondaKeyring.keyring_path = fn

    anaconda_keyring = AnacondaKeyring()
    assert anaconda_keyring.get_password("s", "u") is None

    with pytest.raises(PasswordDeleteError):
        anaconda_keyring.delete_password("s", "u")


def test_anaconda_keyring_not_writable(tmp_path: Path) -> None:
    from anaconda_auth.token import AnacondaKeyring

    AnacondaKeyring.keyring_path = tmp_path / "keyring"
    AnacondaKeyring.keyring_path.touch()
    AnacondaKeyring.keyring_path.chmod(0x444)

    assert not AnacondaKeyring.viable


def test_anaconda_keyring_dir_not_a_dir(tmp_path: Path) -> None:
    from anaconda_auth.token import AnacondaKeyring

    keyring_dir = tmp_path / "anaconda"
    keyring_dir.touch()
    AnacondaKeyring.keyring_path = keyring_dir / "keyring"

    assert not AnacondaKeyring.viable


@pytest.fixture()
def expected_api_key() -> str:
    return "one key to rule them all"


@pytest.fixture(params=[("legacy-0", None), ("legacy-1", 1)])
def legacy_token_storage(request, expected_api_key, mocker: MockerFixture) -> str:
    """This fixture prepares the legacy token storage for two legacy domains, and the
    stored version associated with that domain. The assertions confirm the state of the
    keyring for each state.
    """
    mocker.patch.dict(
        anaconda_auth.token.MIGRATIONS, {"modern": ["legacy-1", "legacy-0"]}
    )

    legacy_domain, legacy_version = request.param

    # First make a token in the keyring with the legacy domain
    legacy_token = TokenInfo(
        api_key=expected_api_key, domain=legacy_domain, version=legacy_version
    )
    assert legacy_token.version is legacy_version
    legacy_token.save()

    payload = keyring.get_password(anaconda_auth.token.KEYRING_NAME, legacy_domain)
    assert payload is not None

    decoded = TokenInfo._decode(payload)
    if legacy_version is None:
        assert "version" not in decoded
    else:
        assert decoded["version"] == legacy_version

    payload = keyring.get_password(anaconda_auth.token.KEYRING_NAME, "modern")
    assert payload is None


def test_anaconda_keyring_domain_migration(
    expected_api_key: str, legacy_token_storage: None
) -> None:
    """Any of the legacy domains are migrated to the modern domain."""
    token = TokenInfo.load(domain="modern")
    assert token.api_key == expected_api_key
    assert token.version == 2

    payload = keyring.get_password(anaconda_auth.token.KEYRING_NAME, "legacy-0")
    assert payload is None

    payload = keyring.get_password(anaconda_auth.token.KEYRING_NAME, "legacy-1")
    assert payload is None

    payload = keyring.get_password(anaconda_auth.token.KEYRING_NAME, "modern")
    assert payload is not None

    decoded = TokenInfo._decode(payload)
    assert decoded["version"] == 2


def test_init_token_info_no_domain() -> None:
    """If we create a TokenInfo with no domain, it defaults to the config value."""
    config = AnacondaAuthConfig()
    token_info = TokenInfo()
    assert token_info.domain == config.domain


def test_load_token_info_create_false() -> None:
    with pytest.raises(TokenNotFoundError):
        _ = TokenInfo.load()


def test_load_token_info_create_true_config_domain() -> None:
    config = AnacondaAuthConfig()
    token_info = TokenInfo.load(create=True)
    assert token_info.domain == config.domain


def test_load_token_info_create_true_explicit_domain() -> None:
    expected_domain = "some-site.com"
    token_info = TokenInfo.load(domain=expected_domain, create=True)
    assert token_info.domain == expected_domain


def test_set_repo_token() -> None:
    token_info = TokenInfo()
    token_info.set_repo_token("org-name", "test-token")
    assert token_info.get_repo_token("org-name") == "test-token"


def test_set_repo_token_same_org_overwritten() -> None:
    token_info = TokenInfo()
    assert len(token_info.repo_tokens) == 0

    # Write the first token
    token_info.set_repo_token("org-name", "test-token")
    assert token_info.get_repo_token("org-name") == "test-token"
    assert len(token_info.repo_tokens) == 1

    # Token gets overwritten
    token_info.set_repo_token("org-name", "another-test-token")
    assert token_info.get_repo_token("org-name") == "another-test-token"
    assert len(token_info.repo_tokens) == 1


def test_set_repo_token_different_organization() -> None:
    token_info = TokenInfo()
    assert len(token_info.repo_tokens) == 0

    # Write the first token
    token_info.set_repo_token("org-name", "test-token")
    assert token_info.get_repo_token("org-name") == "test-token"
    assert len(token_info.repo_tokens) == 1

    # Write another token for a different organization
    token_info.set_repo_token("another-org-name", "another-test-token")
    assert token_info.get_repo_token("another-org-name") == "another-test-token"
    assert len(token_info.repo_tokens) == 2


def test_delete_repo_token() -> None:
    token_info = TokenInfo()
    assert len(token_info.repo_tokens) == 0

    # Write the first token
    token_info.set_repo_token("org-name", "test-token")
    assert token_info.get_repo_token("org-name") == "test-token"
    assert len(token_info.repo_tokens) == 1

    # Write another token for a different organization
    token_info.set_repo_token("another-org-name", "another-test-token")
    assert token_info.get_repo_token("another-org-name") == "another-test-token"
    assert len(token_info.repo_tokens) == 2

    # Delete the first token
    token_info.delete_repo_token("org-name")
    assert len(token_info.repo_tokens) == 1
    with pytest.raises(TokenNotFoundError):
        token_info.get_repo_token("org-name")


@pytest.mark.parametrize("saved_domain", ["anaconda.cloud", "anaconda.com"])
def test_token_reload_after_migration_via_anaconda_cloud_config(
    saved_domain: str,
) -> None:
    # Save the token (i.e. after login) to new and legacy domain in keyring
    original_token = TokenInfo(api_key="TEST_KEY", domain=saved_domain)
    original_token.save()

    # Now, load it via the explicit use of the AnacondaCloudConfig object with no
    # domain override. This is what the Assistant is doing. Since the token should
    # be migrated to anaconda.com when loading it if it is anaconda.cloud, this will
    # work when the AnacondaCloudConfig.domain default is anaconda.com.
    config = AnacondaCloudConfig()
    loaded_token = TokenInfo.load(domain=config.domain)
    assert loaded_token.api_key == "TEST_KEY"


@pytest.mark.parametrize(
    "saved_domains",
    [
        ["anaconda.cloud"],
        ["anaconda.com"],
        ["anaconda.cloud", "anaconda.com"],
    ],
)
def test_logout_removes_anaconda_cloud_tokens(saved_domains: str) -> None:
    # Given: The token is saved in keyring in either domain, or both
    for saved_domain in saved_domains:
        original_token = TokenInfo(api_key="TEST_KEY", domain=saved_domain)
        original_token.save()

    # When: I logout
    logout()

    # Then: neither of the domains contain a token
    for domain in ["anaconda.com", "anaconda.cloud"]:
        with pytest.raises(TokenNotFoundError):
            TokenInfo.load(domain)
