# pyright: reportUnknownMemberType=none
from urllib.parse import parse_qs, urlsplit

import oic
import oic.oic
import oic.oic.message
from faker import Faker
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

faker = Faker()


class AuthorizationError(Exception):
    def __init__(self, error: str, description: str | None = None) -> None:
        self.error = error
        self.description = description

        msg = f"Authorization failed: {error}"
        if description:
            msg = f"{msg}: {description}"

        super().__init__(msg)


class OidcClient:
    """A more practical wrapper for ``oic.oic.Client``"""

    _oic_client: oic.oic.Client
    _authmethod: str

    def __init__(
        self,
        provider_url: str,
        *,
        id: str | None = None,
        redirect_uri: str | None = None,
        auth_method: str = "client_secret_basic",
        secret: str | None = None,
    ) -> None:
        self._oic_client = oic.oic.Client(client_authn_method=CLIENT_AUTHN_METHOD)
        self._oic_client.provider_config(provider_url)

        self._oic_client.store_registration_info({
            "client_id": id or str(faker.uuid4()),
            "client_secret": secret or faker.password(),
        })

        if redirect_uri is None:
            redirect_uri = faker.uri(schemes=["https"])

        self._oic_client.redirect_uris = [redirect_uri]
        self._auth_method = auth_method

    @classmethod
    def register(
        cls,
        provider_url: str,
        redirect_uri: str | None = None,
        auth_method: str = "client_secret_basic",
    ):
        """Register a client with the OpenID provider and instantiate it."""
        oic_client = oic.oic.Client(client_authn_method=CLIENT_AUTHN_METHOD)
        oic_client.provider_config(provider_url)

        if redirect_uri is None:
            redirect_uri = faker.uri(schemes=["https"])

        oic_client.register(
            oic_client.registration_endpoint,  # type: ignore
            token_endpoint_auth_method=auth_method,
            redirect_uris=[redirect_uri],
        )

        return cls(
            provider_url,
            id=oic_client.client_id,  # pyright: ignore[reportUnknownArgumentType]
            redirect_uri=redirect_uri,
            secret=oic_client.client_secret,  # pyright: ignore[reportUnknownArgumentType]
        )

    @property
    def secret(self) -> str:
        secret = self._oic_client.client_secret  # pyright: ignore[reportUnknownVariableType]
        assert isinstance(secret, str)
        return secret

    @property
    def id(self) -> str:
        id = self._oic_client.client_id  # pyright: ignore[reportUnknownVariableType]
        assert isinstance(id, str)
        return id

    def build_authorization_request(
        self,
        *,
        state: str,
        scope: str = "openid",
        response_type: str = "code",
        nonce: str | None = None,
    ):
        request_args = {
            "response_type": response_type,
            "state": state,
            "scope": scope,
        }

        if nonce is not None:
            request_args["nonce"] = nonce
        return self._oic_client.construct_AuthorizationRequest(
            request_args=request_args
        ).request(self._oic_client.authorization_endpoint)

    def fetch_token(
        self, auth_response_location: str, state: str, *, auth_method: str | None = None
    ) -> oic.oic.message.AccessTokenResponse | oic.oic.message.TokenErrorResponse:
        """Parse authorization endpoint response embedded in the redirect location
        and fetches the token.


        :raises AuthorizationError: if authorization was unsuccessful.
        """
        location = urlsplit(auth_response_location)
        response = self._oic_client.parse_response(
            oic.oic.message.AuthorizationResponse,
            info=location.query,
            sformat="urlencoded",
        )
        if isinstance(response, oic.oic.message.AuthorizationErrorResponse):
            raise AuthorizationError(
                response["error"],
                response.get("error_description"),  # pyright: ignore[reportUnknownArgumentType]
            )

        assert parse_qs(location.query)["state"] == [state]
        response = self._oic_client.do_access_token_request(
            state=state,
            code=response["code"],
            authn_method=auth_method or self._auth_method,
        )

        assert isinstance(
            response,
            oic.oic.message.AccessTokenResponse | oic.oic.message.TokenErrorResponse,
        )

        return response

    def fetch_userinfo(
        self, token: str
    ) -> oic.oic.message.OpenIDSchema | oic.oic.message.UserInfoErrorResponse:
        response = self._oic_client.do_user_info_request(token=token)  # pyright: ignore[reportUnknownVariableType]
        assert isinstance(
            response,
            oic.oic.message.OpenIDSchema | oic.oic.message.UserInfoErrorResponse,
        )
        return response
