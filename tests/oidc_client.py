"""
Experimental OpenID Connect client (Relying Party).
"""

import dataclasses
import secrets
from collections.abc import Sequence
from typing import Literal, Self, cast
from urllib.parse import parse_qs, urlencode, urlsplit

import authlib
import httpx
import pydantic


@dataclasses.dataclass(kw_only=True, frozen=True)
class ProviderConfiguration:
    """
    https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
    """

    @staticmethod
    def fetch(issuer_url: str) -> "ProviderConfiguration":
        # TODO: vaidate issuer url
        response = httpx.get(f"{issuer_url}/.well-known/openid-configuration")
        response.raise_for_status()
        return ProviderConfiguration.decode(response.json())

    @staticmethod
    def decode(data: object) -> "ProviderConfiguration":
        # cache type adapter
        return pydantic.TypeAdapter(ProviderConfiguration).validate_python(data)

    issuer: str
    # TODO: validate URL (scheme, no query, no fragment)
    """
    REQUIRED. URL using the https scheme with no query or fragment components 
    that the OP asserts as its Issuer Identifier.
    """

    authorization_endpoint: str
    """
    REQUIRED. URL of the OP's OAuth 2.0 Authorization Endpoint.
    """

    response_types_supported: Sequence[str]
    """
    REQUIRED. JSON array containing a list of the OAuth 2.0 response_type values 
    that this OP supports. Dynamic OpenID Providers MUST support 'code', 'id_token',
    and 'id_token token'.
    """

    jwks_uri: str
    """
    REQUIRED. URL of the OP's JWK Set document.
    """

    subject_types_supported: list[Literal["pairwise", "public"]]
    """
    REQUIRED. JSON array containing a list of the Subject Identifier types that this OP supports.
    Valid types include 'pairwise' and 'public'.
    """

    id_token_signing_alg_values_supported: list[str]
    """
    REQUIRED. JSON array containing a list of the JWS signing algorithms supported by the OP for the ID Token.
    The algorithm 'RS256' MUST be included.
    """

    token_endpoint: str | None = None
    """
    URL of the OP's OAuth 2.0 Token Endpoint.
    This is REQUIRED unless only the Implicit Flow is used.
    """

    userinfo_endpoint: str | None = None
    """
    RECOMMENDED. URL of the OP's UserInfo Endpoint.
    """

    registration_endpoint: str | None = None
    """
    RECOMMENDED. URL of the OP's Dynamic Client Registration Endpoint.
    """

    scopes_supported: list[str] | None = None
    """
    RECOMMENDED. JSON array containing a list of the OAuth 2.0 scope values 
    that this server supports, including the 'openid' scope.
    """

    response_modes_supported: list[str] | None = None
    """
    OPTIONAL. JSON array containing a list of the OAuth 2.0 response_mode values that this OP supports.
    Default for Dynamic OpenID Providers is ["query", "fragment"].
    """

    grant_types_supported: list[Literal["authorization_code", "implicit"]] | None = None
    """
    OPTIONAL. JSON array containing a list of the OAuth 2.0 Grant Type values that this OP supports.
    Dynamic OpenID Providers MUST support 'authorization_code' and 'implicit' Grant Types.
    """

    acr_values_supported: list[str] | None = None
    """
    OPTIONAL. JSON array containing a list of the Authentication Context Class References supported by this OP.
    """

    id_token_encryption_alg_values_supported: list[str] | None = None
    """
    OPTIONAL. JSON array containing a list of the JWE encryption algorithms supported by the OP for the ID Token.
    """

    id_token_encryption_enc_values_supported: list[str] | None = None
    """
    OPTIONAL. JSON array containing a list of the JWE encryption algorithms supported by the OP for the ID Token.
    """

    userinfo_signing_alg_values_supported: list[str] | None = None
    """
    OPTIONAL. JSON array containing a list of the JWS signing algorithms supported by the UserInfo Endpoint.
    """

    userinfo_encryption_alg_values_supported: list[str] | None = None
    """
    OPTIONAL. JSON array containing a list of the JWE encryption algorithms supported by the UserInfo Endpoint.
    """

    userinfo_encryption_enc_values_supported: list[str] | None = None
    """
    OPTIONAL. JSON array containing a list of the JWE encryption algorithms supported by the UserInfo Endpoint.
    """

    request_object_signing_alg_values_supported: list[str] | None = None
    """
    OPTIONAL. JSON array containing a list of the JWS signing algorithms supported by the OP for Request Objects.
    """

    request_object_encryption_alg_values_supported: list[str] | None = None
    """
    OPTIONAL. JSON array containing a list of the JWE encryption algorithms supported by the OP for Request Objects.
    """

    request_object_encryption_enc_values_supported: list[str] | None = None
    """
    OPTIONAL. JSON array containing a list of the JWE encryption algorithms supported by the OP for Request Objects.
    """

    token_endpoint_auth_methods_supported: (
        list[
            Literal[
                "client_secret_post",
                "client_secret_basic",
                "client_secret_jwt",
                "private_key_jwt",
            ]
        ]
        | None
    ) = None
    """
    OPTIONAL. JSON array containing a list of Client Authentication methods supported by this Token Endpoint.
    """

    token_endpoint_auth_signing_alg_values_supported: list[str] | None = None
    """
    OPTIONAL. JSON array containing a list of the JWS signing algorithms supported by the Token Endpoint for the signature.
    """

    display_values_supported: list[str] | None = None
    """
    OPTIONAL. JSON array containing a list of the display parameter values supported by the OpenID Provider.
    """

    claim_types_supported: list[str] | None = None
    """
    OPTIONAL. JSON array containing a list of the Claim Types that the OpenID Provider supports.
    """

    claims_supported: list[str] | None = None
    """
    RECOMMENDED. JSON array containing a list of the Claim Names that the OpenID Provider MAY supply values for.
    """

    service_documentation: str | None = None
    """
    OPTIONAL. URL of a page containing human-readable information that developers might need when using the OpenID Provider.
    """

    claims_locales_supported: list[str] | None = None
    """
    OPTIONAL. Languages and scripts supported for values in Claims being returned, represented as a JSON array of language tag values.
    """

    ui_locales_supported: list[str] | None = None
    """
    OPTIONAL. Languages and scripts supported for the user interface, represented as a JSON array of language tag values.
    """

    claims_parameter_supported: bool | None = None
    """
    OPTIONAL. Boolean value specifying whether the OP supports the claims parameter.
    """

    request_parameter_supported: bool | None = None
    """
    OPTIONAL. Boolean value specifying whether the OP supports the request parameter.
    """

    request_uri_parameter_supported: bool | None = None
    """
    OPTIONAL. Boolean value specifying whether the OP supports the request_uri parameter.
    """

    require_request_uri_registration: bool | None = None
    """
    OPTIONAL. Boolean value specifying whether the OP requires any request_uri values used to be pre-registered.
    """

    op_policy_uri: str | None = None
    """
    OPTIONAL. URL that the OpenID Provider provides to read about the OP's requirements for the Relying Party.
    """

    op_tos_uri: str | None = None
    """
    OPTIONAL. URL that the OpenID Provider provides to read about its terms of service.
    """

    def as_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(kw_only=True, frozen=True)
class AuthorizationRequest:
    url: str
    state: str
    nonce: str | None
    client_id: str


def start_authorization(
    provider_config: ProviderConfiguration,
    *,
    client_id: str,
    # TODO: client_secret: str,
    redirect_uri: str,
    nonce: bool = True,
) -> AuthorizationRequest:
    """Create an authentication request for the authorization code flow.

    https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
    """
    # TODO: check "openid in scoe"
    state = secrets.token_urlsafe(16)

    if nonce:
        nonce_value = secrets.token_urlsafe(16)
    else:
        nonce_value = None

    query = {
        "state": state,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "nonce": nonce_value,
    }

    url = urlsplit(provider_config.authorization_endpoint)
    url = url._replace(query=urlencode(query)).geturl()
    return AuthorizationRequest(
        url=url,
        state=state,
        nonce=nonce_value,
        client_id=client_id,
    )


@dataclasses.dataclass(kw_only=True, frozen=True)
class TokenResult:
    access_token: str
    """OAuth2 bearer token for accessing resources on behalf of the authenticated
    user."""

    claims: dict[str, str]
    """Claims contained in the JWT ID token.

    See https://openid.net/specs/openid-connect-core-1_0.html#Claims"""


@dataclasses.dataclass
class TokenResponse:
    """Response from OpenID Connect token endpoint.

    See https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse"""

    access_token: str
    id_token: str

    @classmethod
    def decode(cls, data: object) -> Self:
        # cache type adapter
        return pydantic.TypeAdapter(cls).validate_python(data)


def get_token(
    openid_config: ProviderConfiguration,
    request: AuthorizationRequest,
    query_string: str,
) -> TokenResult:
    """Fetch the ID Token and Access Token using the code from a successful
    authorization response encoded in `query_string`.
    """
    # TODO: Extract query string parsing and state validation to a seaparter
    # method

    # TODO: return access_token, refresh_token, etc
    query = parse_qs(query_string)

    # TODO: handle errors

    # TODO: raise exception
    assert query["state"] == [request.state]

    # TODO: ValueError
    code = query["code"][0]

    # TODO: ValueError
    assert openid_config.token_endpoint

    response = httpx.post(openid_config.token_endpoint, data={"code": code})
    response.raise_for_status()
    token_response = TokenResponse.decode(response.json())

    keys = httpx.get(openid_config.jwks_uri).json()
    keys = authlib.jose.JsonWebKey.import_key_set(keys)  # type: ignore

    claims = authlib.jose.JsonWebToken(["RS256"]).decode(token_response.id_token, keys)  # type: ignore
    claims = cast("dict[str, str]", claims)

    # TODO: check claims
    assert claims["iss"] == openid_config.issuer
    assert claims["aud"] == request.client_id
    if request.nonce is not None or "nonce" in claims:
        assert claims["nonce"] == request.nonce

    return TokenResult(
        access_token=token_response.access_token,
        claims=claims,
    )
