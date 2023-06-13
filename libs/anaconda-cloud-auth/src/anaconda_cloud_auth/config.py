import os
from typing import Optional

import pydantic
import requests
from pydantic import BaseModel
from pydantic import BaseSettings
from pydantic import Field


class CLIAuthConfig(BaseSettings):
    auth_domain: str = Field(
        ...,  # Required
        title="Auth Domain",
        description="The domain the auth requests should go to. ie: my-slug.projects.oryapis.com",
    )

    client_id: Optional[str] = None
    client_secret: Optional[str] = None

    host_name: str = "127.0.0.1"
    port: int = 8000
    oidc_path: str = "/auth/oidc"
    cache_control: str = "no-cache, no-store, must-revalidate, max-age=0, s-maxage=0"

    openid_config_path: str = Field(
        default=".well-known/openid-configuration",
        title="OpenID Configuration Path",
        description="The path to the open-id configuration json. Typically '.well-known/openid-configuration'",
    )

    @property
    def redirect_uri(self: "CLIAuthConfig") -> str:
        """The local URI where we will listen for the authorization code."""
        return f"http://{self.host_name}:{self.port}{self.oidc_path}"

    @property
    def well_known_url(self: "CLIAuthConfig") -> str:
        """The URL from which to load the OpenID configuration."""
        return f"https://{self.auth_domain}/{self.openid_config_path}"

    @property
    def oidc(self) -> "OpenIDConfiguration":
        """The OIDC configuration, cached as a regular instance attribute."""
        return self.__dict__.setdefault(
            "_oidc", OpenIDConfiguration.from_auth_config(self)
        )


class OpenIDConfiguration(BaseModel):
    # TODO: Remove the hard-coded default, return from IAM
    issuer: str = os.getenv(
        "BASE_URL", "https://anaconda.cloud"
    )

    # TODO: Remove the hard-coded default, return from IAM
    authorization_endpoint: str = os.getenv(
        "IAM_AUTH_ENDPOINT", "https://anaconda.cloud/authorize"
    )
    userinfo_endpoint: Optional[str] = None
    token_endpoint: str
    revocation_endpoint: Optional[str] = None
    end_session_endpoint: Optional[str] = None

    jwks_uri: str

    subject_types_supported: list[str] = []
    response_types_supported: list[str] = []
    claims_supported: list[str] = []
    grant_types_supported: list[str] = []
    response_modes_supported: list[str] = []
    scopes_supported: list[str] = []
    token_endpoint_auth_methods_supported: list[str] = []
    userinfo_signing_alg_values_supported: list[str] = []
    id_token_signing_alg_values_supported: list[str] = []
    userinfo_signed_response_alg: list[str] = []
    id_token_signed_response_alg: list[str] = []
    request_object_signing_alg_values_supported: list[str] = []
    code_challenge_methods_supported: list[str] = []

    request_parameter_supported: bool = False
    request_uri_parameter_supported: bool = False
    require_request_uri_registration: bool = False
    claims_parameter_supported: bool = False
    backchannel_logout_supported: bool = False
    backchannel_logout_session_supported: bool = False
    frontchannel_logout_supported: bool = False
    frontchannel_logout_session_supported: bool = False

    @classmethod
    def from_auth_config(
        cls: type["OpenIDConfiguration"], auth_config: CLIAuthConfig
    ) -> "OpenIDConfiguration":
        oidc_config: dict = requests.get(auth_config.well_known_url).json()
        return cls.parse_obj(oidc_config)

    @pydantic.validator("token_endpoint")
    def fix_token_endpoint(cls, value: str) -> str:
        # TODO: Remove after dev IAM fixed
        return value.replace("/public/", "/api/iam/")


# Global config object, loaded once.
_config: CLIAuthConfig | None = None


def get_config(use_ory: bool = False) -> CLIAuthConfig:
    global _config

    if not _config:
        if use_ory:
            _config = CLIAuthConfig(
                auth_domain=os.environ["ORY_AUTH_DOMAIN"],
                client_id=os.environ["ORY_CLIENT_ID"],
            )
        else:
            _config = CLIAuthConfig(
                auth_domain=os.getenv("IAM_AUTH_DOMAIN", "anaconda.cloud/api/iam"),
                client_id=os.getenv("IAM_CLIENT_ID"),
                client_secret=os.getenv("IAM_CLIENT_SECRET"),
            )
    return _config
