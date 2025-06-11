import asyncio
import ipaddress
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlparse

from smithy_core import URI
from smithy_core.aio.interfaces.identity import IdentityResolver
from smithy_core.exceptions import SmithyIdentityError
from smithy_http import Field, Fields
from smithy_http.aio import HTTPRequest
from smithy_http.aio.interfaces import HTTPClient

from .identity import AWSCredentialsIdentity, AWSIdentityProperties

_CONTAINER_METADATA_IP = "169.254.170.2"
_CONTAINER_METADATA_ALLOWED_HOSTS = {
    _CONTAINER_METADATA_IP,
    "169.254.170.23",
    "fd00:ec2::23",
    "localhost",
}
_DEFAULT_TIMEOUT = 2
_DEFAULT_RETRIES = 3
_SLEEP_SECONDS = 1


@dataclass
class ContainerCredentialConfig:
    timeout: int = _DEFAULT_TIMEOUT
    retries: int = _DEFAULT_RETRIES


class ContainerMetadataClient:
    def __init__(self, http_client: HTTPClient, config: ContainerCredentialConfig):
        self._http_client = http_client
        self._config = config

    def _validate_allowed_url(self, uri: URI) -> None:
        if self._is_loopback(uri.host):
            return

        if not self._is_allowed_container_metadata_host(uri.host):
            raise SmithyIdentityError(
                f"Unsupported host '{uri.host}'. "
                f"Can only retrieve metadata from a loopback address or "
                f"one of: {', '.join(_CONTAINER_METADATA_ALLOWED_HOSTS)}"
            )

    async def get_credentials(self, uri: URI, fields: Fields) -> dict:
        self._validate_allowed_url(uri)
        fields.set_field(Field(name="Accept", values=["application/json"]))

        attempts = 0
        last_exc = None
        while attempts < self._config.retries:
            try:
                request = HTTPRequest(
                    method="GET",
                    destination=uri,
                    fields=fields,
                )
                response = await self._http_client.send(request)
                body = await response.consume_body_async()
                if response.status_code != 200:
                    raise SmithyIdentityError(
                        f"Container metadata service returned {response.status_code}: "
                        f"{body.decode('utf-8')}"
                    )
                try:
                    return json.loads(body.decode("utf-8"))
                except Exception as e:
                    raise SmithyIdentityError(
                        f"Unable to parse JSON from container metadata: {body.decode('utf-8')}"
                    ) from e
            except Exception as exc:
                last_exc = exc
                await asyncio.sleep(_SLEEP_SECONDS)
                attempts += 1

        raise SmithyIdentityError(
            f"Failed to retrieve container metadata after {self._config.retries} attempts"
        ) from last_exc

    def _is_loopback(self, hostname: str) -> bool:
        try:
            return ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            return False

    def _is_allowed_container_metadata_host(self, hostname: str) -> bool:
        return hostname in _CONTAINER_METADATA_ALLOWED_HOSTS


class ContainerCredentialResolver(
    IdentityResolver[AWSCredentialsIdentity, AWSIdentityProperties]
):
    """
    Resolves AWS Credentials from container credential sources.
    """

    ENV_VAR = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
    ENV_VAR_FULL = "AWS_CONTAINER_CREDENTIALS_FULL_URI"
    ENV_VAR_AUTH_TOKEN = "AWS_CONTAINER_AUTHORIZATION_TOKEN"
    ENV_VAR_AUTH_TOKEN_FILE = "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"

    def __init__(
        self,
        http_client: HTTPClient,
        config: ContainerCredentialConfig = None,
    ):
        self._http_client = http_client
        self._config = config or ContainerCredentialConfig()
        # These must be awaited, so moved to get_identity
        self._client = ContainerMetadataClient(http_client, self._config)
        self._credentials = None

    async def _resolve_uri_from_env(self) -> URI:
        if self.ENV_VAR in os.environ:
            return URI(
                scheme="http", host=_CONTAINER_METADATA_IP, path=os.environ[self.ENV_VAR]
            )
        elif self.ENV_VAR_FULL in os.environ:
            parsed = urlparse(os.environ[self.ENV_VAR_FULL])
            return URI(
                scheme=parsed.scheme,
                host=parsed.hostname,
                port=parsed.port,
                path=parsed.path,
            )
        else:
            raise SmithyIdentityError(
                f"Neither {self.ENV_VAR} or {self.ENV_VAR_FULL} environment "
                "variables are set. Unable to resolve credentials."
            )

    async def _resolve_fields_from_env(self) -> Fields:
        fields = Fields()
        if self.ENV_VAR_AUTH_TOKEN_FILE in os.environ:
            try:
                with open(os.environ[self.ENV_VAR_AUTH_TOKEN_FILE], "r", encoding="utf-8") as f:
                    auth_token = f.read().strip()
            except (FileNotFoundError, PermissionError) as e:
                raise SmithyIdentityError(
                    f"Unable to open {os.environ[self.ENV_VAR_AUTH_TOKEN_FILE]}."
                ) from e

            fields.set_field(Field(name="Authorization", values=[auth_token]))
        elif self.ENV_VAR_AUTH_TOKEN in os.environ:
            auth_token = os.environ[self.ENV_VAR_AUTH_TOKEN]
            fields.set_field(Field(name="Authorization", values=[auth_token]))

        return fields

    async def get_identity(
        self, *, properties: AWSIdentityProperties
    ) -> AWSCredentialsIdentity:
        uri = await self._resolve_uri_from_env()
        fields = await self._resolve_fields_from_env()
        creds = await self._client.get_credentials(uri, fields)
        access_key_id = creds.get("AccessKeyId")
        secret_access_key = creds.get("SecretAccessKey")
        session_token = creds.get("Token")
        expiration = creds.get("Expiration")
        account_id = creds.get("AccountId", None)

        if expiration is not None:
            expiration = datetime.fromisoformat(expiration).replace(tzinfo=UTC)

        if access_key_id is None or secret_access_key is None:
            raise SmithyIdentityError(
                "AccessKeyId and SecretAccessKey are required for container credentials"
            )

        self._credentials = AWSCredentialsIdentity(
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token,
            expiration=expiration,
            account_id=account_id,
        )
        return self._credentials
