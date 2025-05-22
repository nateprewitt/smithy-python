import asyncio
import ipaddress
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime

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
_DEFAULT_SLEEP_SECONDS = 1


@dataclass(init=False)
class ContainerCredentialConfig:
    endpoint: URI
    timeout: int
    retries: int

    def __init__(
        self,
        endpoint: URI = None,
        timeout: int = _DEFAULT_TIMEOUT,
        retries: int = _DEFAULT_RETRIES,
    ):
        self.endpoint = endpoint or URI(scheme="http", host=_CONTAINER_METADATA_IP)
        self.timeout = timeout
        self.retries = retries


class ContainerMetadataClient:
    def __init__(self, http_client: HTTPClient, config: ContainerCredentialConfig):
        self._http_client = http_client
        self._config = config

    @staticmethod
    def _validate_allowed_url(uri: URI) -> None:
        if self._is_loopback(uri.host):
            return

        if not self._is_allowed_container_metadata_host(uri.host):
            raise SmithyIdentityError(
                f"Unsupported host '{hostname}'. "
                f"Can only retrieve metadata from a loopback address or "
                f"one of: {', '.join(_CONTAINER_METADATA_ALLOWED_HOSTS)}"
            )

    async def _retrieve(self, uri: URI, headers: Fields | None = None) -> dict:
        self._validate_allowed_url(uri)

        attempts = 0
        last_exc = None
        while attempts < self._config.retries:
            try:
                request = HTTPRequest(
                    method="GET",
                    destination=uri,
                    fields=headers or Fields([Field(name="Accept", values=["application/json"])]),
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

    async def get_credentials(self, relative_uri: str) -> dict:
        uri = URI(
            scheme=self._config.endpoint.scheme,
            host=self._config.endpoint.host,
            port=self._config.endpoint.port,
            path=relative_uri,
        )
        return await self._retrieve(uri)

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

    def __init__(
        self,
        http_client: HTTPClient,
        config: ContainerCredentialConfig = None,
        relative_uri: str = None,
    ):
        self._http_client = http_client
        self._config = config or ContainerCredentialConfig()
        self._relative_uri = relative_uri or self._get_relative_uri_from_env()
        self._client = ContainerMetadataClient(http_client, self._config)
        self._credentials = None

    @staticmethod
    def _get_relative_uri_from_env() -> str:
        uri = os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
        if not uri:
            raise SmithyIdentityError("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI environment variable is not set")
        return uri

    async def get_identity(
        self, *, properties: AWSIdentityProperties
    ) -> AWSCredentialsIdentity:
        creds = await self._client.get_credentials(self._relative_uri)
        access_key_id = creds.get("AccessKeyId")
        secret_access_key = creds.get("SecretAccessKey")
        session_token = creds.get("Token")
        expiration = creds.get("Expiration")
        account_id = creds.get("AccountId", None)

        if expiration is not None:
            expiration = datetime.fromisoformat(expiration.replace("Z", "+00:00")).replace(tzinfo=UTC)

        if access_key_id is None or secret_access_key is None:
            raise SmithyIdentityError("AccessKeyId and SecretAccessKey are required for container credentials")

        return AWSCredentialsIdentity(
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            session_token=session_token,
            expiration=expiration,
            account_id=account_id,
        )
