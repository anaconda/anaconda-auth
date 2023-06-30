from typing import List

import requests
from pydantic import BaseModel
from pydantic import BaseSettings


class APIConfig(BaseSettings):
    class Config:
        env_prefix = "ANACONDA_CLOUD_API_"
        env_file = ".env"

    domain: str = "anaconda.cloud"


class AuthConfig(BaseSettings):
    class Config:
        env_prefix = "ANACONDA_CLOUD_AUTH_"
        env_file = ".env"

    domain: str = "anaconda.cloud/api/iam"
    client_id: str = "b4ad7f1d-c784-46b5-a9fe-106e50441f5a"
    redirect_uri: str = "http://127.0.0.1:8000/auth/oidc"
    openid_config_path: str = ".well-known/openid-configuration"

    @property
    def well_known_url(self: "AuthConfig") -> str:
        """The URL from which to load the OpenID configuration."""
        return f"https://{self.domain}/{self.openid_config_path}"

    @property
    def oidc(self) -> "OpenIDConfiguration":
        """The OIDC configuration, cached as a regular instance attribute."""
        res = requests.get(self.well_known_url)
        res.raise_for_status()
        oidc_config = OpenIDConfiguration(**res.json())
        return self.__dict__.setdefault("_oidc", oidc_config)


class OpenIDConfiguration(BaseModel):
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str

    id_token_signing_alg_values_supported: List[str] = []
