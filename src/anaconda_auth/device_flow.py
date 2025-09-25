"""
Device Code Flow implementation for OAuth 2.0 device authorization grant (RFC 8628).
"""

import json
import time
from typing import Dict
from typing import Optional
from typing import Tuple

import requests

from anaconda_auth.exceptions import DeviceFlowDenied
from anaconda_auth.exceptions import DeviceFlowError
from anaconda_auth.exceptions import DeviceFlowTimeout


class DeviceCodeFlow:
    """
    OAuth 2.0 Device Code Flow implementation.

    This implements RFC 8628 for devices that are either browserless
    or have limited input capabilities.
    """

    def __init__(
        self,
        auth_url: str,
        client_id: str,
        scopes: Optional[str] = None,
        timeout: int = 300,  # 5 minutes default
        ssl_verify: bool = True,
    ):
        """
        Initialize device code flow.

        Args:
            auth_url: Base URL of the authorization server
            client_id: OAuth client identifier
            scopes: Space-separated list of requested scopes
            timeout: Maximum time to wait for user authorization (seconds)
            ssl_verify: Whether to verify SSL certificates
        """
        self.auth_url = auth_url.rstrip("/")
        self.client_id = client_id
        self.scopes = scopes or "openid email profile"
        self.timeout = timeout
        self.ssl_verify = ssl_verify

        # Will be populated from well-known config
        self.device_authorization_endpoint = None
        self.token_endpoint = None

        # Device authorization response data
        self.device_code = None
        self.user_code = None
        self.verification_uri = None
        self.verification_uri_complete = None
        self.expires_in = None
        self.interval = 5  # Default polling interval

    def _discover_endpoints(self) -> None:
        """Discover OAuth endpoints from well-known configuration."""
        well_known_url = f"{self.auth_url}/.well-known/openid-configuration"

        try:
            response = requests.get(well_known_url, verify=self.ssl_verify)
            response.raise_for_status()
            config = response.json()

            self.device_authorization_endpoint = config.get(
                "device_authorization_endpoint"
            )
            self.token_endpoint = config.get("token_endpoint")

            if not self.device_authorization_endpoint:
                raise DeviceFlowError(
                    "Device authorization endpoint not found in well-known configuration"
                )
            if not self.token_endpoint:
                raise DeviceFlowError(
                    "Token endpoint not found in well-known configuration"
                )

        except requests.RequestException as e:
            raise DeviceFlowError(f"Failed to discover endpoints: {e}")

    def initiate_device_authorization(self) -> Tuple[str, str]:
        """
        Initiate device authorization request.

        Returns:
            Tuple of (user_code, verification_uri) to display to user
        """
        if not self.device_authorization_endpoint:
            self._discover_endpoints()

        data = {"client_id": self.client_id, "scope": self.scopes}

        try:
            response = requests.post(
                self.device_authorization_endpoint,
                data=data,
                verify=self.ssl_verify,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()

            auth_response = response.json()

            # Store response data
            self.device_code = auth_response["device_code"]
            self.user_code = auth_response["user_code"]
            self.verification_uri = auth_response["verification_uri"]
            self.verification_uri_complete = auth_response.get(
                "verification_uri_complete"
            )
            self.expires_in = auth_response.get("expires_in", 1800)  # 30 min default
            self.interval = auth_response.get("interval", 5)

            return self.user_code, self.verification_uri

        except requests.RequestException as e:
            raise DeviceFlowError(f"Device authorization request failed: {e}")
        except KeyError as e:
            raise DeviceFlowError(f"Missing required field in response: {e}")

    def poll_for_token(self) -> Dict[str, str]:
        """
        Poll the token endpoint until authorization is complete.

        Returns:
            Token response containing access_token, etc.
        """
        if not self.device_code:
            raise DeviceFlowError("Must call initiate_device_authorization first")

        start_time = time.time()

        while time.time() - start_time < self.timeout:
            try:
                token_response = self._request_token()
                return token_response

            except DeviceFlowTimeout:
                raise
            except DeviceFlowDenied:
                raise
            except DeviceFlowError as e:
                # Check for authorization_pending
                if "authorization_pending" in str(e).lower():
                    time.sleep(self.interval)
                    continue
                elif "slow_down" in str(e).lower():
                    # Server asked us to slow down
                    self.interval = min(self.interval + 5, 30)
                    time.sleep(self.interval)
                    continue
                else:
                    raise

        raise DeviceFlowTimeout("Device authorization timed out")

    def _request_token(self) -> Dict[str, str]:
        """Make a single token request."""
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": self.device_code,
            "client_id": self.client_id,
        }

        try:
            response = requests.post(
                self.token_endpoint,
                data=data,
                verify=self.ssl_verify,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            if response.status_code == 200:
                return response.json()

            # Handle error responses
            try:
                error_data = response.json()
                error_code = error_data.get("error", "unknown_error")
                error_description = error_data.get("error_description", "")

                if error_code == "authorization_pending":
                    raise DeviceFlowError("authorization_pending")
                elif error_code == "slow_down":
                    raise DeviceFlowError("slow_down")
                elif error_code == "expired_token":
                    raise DeviceFlowTimeout("Device code expired")
                elif error_code == "access_denied":
                    raise DeviceFlowDenied("User denied authorization")
                else:
                    raise DeviceFlowError(
                        f"Token request failed: {error_code} - {error_description}"
                    )

            except json.JSONDecodeError:
                response.raise_for_status()

        except requests.RequestException as e:
            raise DeviceFlowError(f"Token request failed: {e}")

    def get_complete_verification_uri(self) -> Optional[str]:
        """Get the complete verification URI if available."""
        return self.verification_uri_complete
