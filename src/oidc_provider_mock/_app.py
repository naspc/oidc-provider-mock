import secrets
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from typing import cast
from uuid import uuid4

import authlib.oauth2.rfc6749
import authlib.oauth2.rfc6749.grants
import authlib.oauth2.rfc6750
import authlib.oidc.core.grants
import flask
import flask.typing
import pydantic
import werkzeug.local
from authlib import jose
from authlib.integrations.flask_oauth2 import (
    AuthorizationServer,
    ResourceProtector,
    current_token,
)
from authlib.oauth2 import OAuth2Request
from authlib.oauth2.rfc6749 import AccessDeniedError
from typing_extensions import override


@dataclass(kw_only=True, frozen=True)
class User:
    sub: str
    claims: dict[str, str] = field(default_factory=dict)
    userinfo: dict[str, object] = field(default_factory=dict)


@dataclass(kw_only=True, frozen=True)
class AuthorizationCode:
    code: str
    client_id: str
    redirect_uri: str
    user_id: str
    nonce: str | None

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return "openid profile"

    def get_nonce(self) -> str | None:
        return self.nonce

    def get_auth_time(self) -> int | None:
        return None


@dataclass(kw_only=True, frozen=True)
class AccessToken:
    token: str
    user_id: str
    scope: str
    expires_at: datetime

    def is_expired(self):
        return datetime.now(timezone.utc) >= self.expires_at

    def is_revoked(self):
        return False

    def get_scope(self) -> str:
        return self.scope

    def get_user(self):
        return storage.get_user(self.user_id)


@dataclass(kw_only=True, frozen=True)
class Client(authlib.oauth2.rfc6749.ClientMixin):
    id: str
    secret: str
    allowed_scopes: Sequence[str] = ("openid", "profile")
    redirect_uris: Sequence[str]

    @override
    def get_client_id(self):
        return self.id

    @override
    def get_default_redirect_uri(self) -> str:
        return self.redirect_uris[0]

    @override
    def get_allowed_scope(self, scope: str) -> str:
        return " ".join(s for s in scope.split() if s in self.allowed_scopes)

    @override
    def check_redirect_uri(self, redirect_uri: str) -> bool:
        return redirect_uri in self.redirect_uris

    @override
    def check_client_secret(self, client_secret: str) -> bool:
        return client_secret == self.secret

    # TODO
    @override
    def check_endpoint_auth_method(self, method: str, endpoint: object):
        """Check if client support the given method for the given endpoint.
        There is a ``token_endpoint_auth_method`` defined via `RFC7591`_.
        Developers MAY re-implement this method with::

            def check_endpoint_auth_method(self, method, endpoint):
                if endpoint == 'token':
                    # if client table has ``token_endpoint_auth_method``
                    return self.token_endpoint_auth_method == method
                return True

        Method values defined by this specification are:

        *  "none": The client is a public client as defined in OAuth 2.0,
            and does not have a client secret.

        *  "client_secret_post": The client uses the HTTP POST parameters
            as defined in OAuth 2.0

        *  "client_secret_basic": The client uses HTTP Basic as defined in
            OAuth 2.0

        .. _`RFC7591`: https://tools.ietf.org/html/rfc7591
        """
        return method in {"client_secret_post", "client_secret_basic"}

    # TODO
    @override
    def check_grant_type(self, grant_type: str):
        """Validate if the client can handle the given grant_type. There are
        four grant types defined by RFC6749:

        * authorization_code
        * implicit
        * client_credentials
        * password

        For instance, there is a ``allowed_grant_types`` column in your client::

            def check_grant_type(self, grant_type):
                return grant_type in self.grant_types

        :param grant_type: the requested grant_type string.
        :return: bool
        """
        return True

    @override
    def check_response_type(self, response_type: str):
        return response_type == "code"


class DummyClient(authlib.oauth2.rfc6749.ClientMixin):
    def __init__(self, id: str) -> None:
        self._id = id

    @override
    def get_client_id(self):
        return self._id

    @override
    def get_default_redirect_uri(self) -> str:
        raise NotImplementedError()

    @override
    def get_allowed_scope(self, scope: str) -> str:
        return scope

    @override
    def check_redirect_uri(self, redirect_uri: str) -> bool:
        return True

    @override
    def check_client_secret(self, client_secret: str) -> bool:
        return True

    @override
    def check_endpoint_auth_method(self, method: str, endpoint: object):
        return True

    @override
    def check_grant_type(self, grant_type: str):
        return True

    @override
    def check_response_type(self, response_type: str):
        return True


class Storage:
    jwk: jose.JsonWebKey

    _clients: dict[str, Client]
    _users: dict[str, User]
    _authorization_codes: dict[str, AuthorizationCode]
    _access_tokens: dict[str, AccessToken]
    _nonces: set[str]

    def __init__(self) -> None:
        self.jwk = jose.RSAKey.generate_key(is_private=True)  # type: ignore
        self._users = {}
        self._authorization_codes = {}
        self._access_tokens = {}
        self._nonces = set()
        self._clients = {}

    def get_user(self, sub: str) -> User | None:
        return self._users.get(sub)

    def store_user(self, user: User):
        self._users[user.sub] = user

    def get_authorization_code(self, code: str) -> AuthorizationCode | None:
        return self._authorization_codes.get(code)

    def store_authorization_code(self, code: AuthorizationCode):
        self._authorization_codes[code.code] = code

    def remove_authorization_code(self, code: str) -> AuthorizationCode | None:
        return self._authorization_codes.pop(code, None)

    def get_access_token(self, token: str) -> AccessToken | None:
        return self._access_tokens.get(token)

    def store_access_token(self, access_token: AccessToken):
        self._access_tokens[access_token.token] = access_token

    def get_client(self, id: str) -> Client | None:
        return self._clients.get(id)

    def store_client(self, client: Client):
        self._clients[client.id] = client

    def add_nonce(self, nonce: str):
        self._nonces.add(nonce)

    def exists_nonce(self, nonce: str) -> bool:
        return nonce in self._nonces


storage = cast(
    "Storage", werkzeug.local.LocalProxy(lambda: flask.g.oidc_provider_mock_storage)
)


class TokenValidator(authlib.oauth2.rfc6750.BearerTokenValidator):
    def authenticate_token(self, token_string: str):
        token = storage.get_access_token(token_string)
        if not token:
            raise AccessDeniedError

        return token


class AuthorizationCodeGrant(authlib.oauth2.rfc6749.AuthorizationCodeGrant):
    def query_authorization_code(
        self, code: str, client: Client | DummyClient
    ) -> AuthorizationCode | None:
        auth_code = storage.get_authorization_code(code)
        if auth_code and auth_code.client_id == client.get_client_id():
            return auth_code

    def delete_authorization_code(self, authorization_code: AuthorizationCode):
        storage.remove_authorization_code(authorization_code.code)

    def authenticate_user(self, authorization_code: AuthorizationCode) -> User | None:
        return storage.get_user(authorization_code.user_id)

    def save_authorization_code(self, code: str, request: object):
        assert isinstance(request, OAuth2Request)
        assert isinstance(request.user, User)
        client = cast("Client | DummyClient", request.client)
        assert isinstance(request.redirect_uri, str)  # type: ignore
        storage.store_authorization_code(
            AuthorizationCode(
                code=code,
                user_id=request.user.sub,
                client_id=client.get_client_id(),
                redirect_uri=request.redirect_uri,
                nonce=request.data.get("nonce"),  # type: ignore
            )
        )


class OpenIdGrantExtension:
    def exists_nonce(self, nonce: str, request: OAuth2Request) -> bool:
        return storage.exists_nonce(nonce)

    def get_jwt_config(self, *args: object, **kwargs: object):
        # TODO
        return {
            "key": storage.jwk,
            "alg": "RS256",
            "exp": 3600,
            "iss": flask.request.host_url.rstrip("/"),
        }

    def generate_user_info(self, user: User, scope: Sequence[str]):
        return {**user.claims, "sub": user.sub}


class OpenIDCode(OpenIdGrantExtension, authlib.oidc.core.OpenIDCode):
    pass


class ImplicitGrant(OpenIdGrantExtension, authlib.oidc.core.OpenIDImplicitGrant):
    pass


class HybridGrant(OpenIdGrantExtension, authlib.oidc.core.OpenIDHybridGrant):
    pass


# TODO: turn  into context variables
authorization = AuthorizationServer()
require_oauth = ResourceProtector()


blueprint = flask.Blueprint("oidc-provider-mock-authlib", __name__)


@dataclass(kw_only=True, frozen=True)
class Config:
    require_client_registration: bool = False


@blueprint.record
def bind_state_to_app_context(setup_state: flask.blueprints.BlueprintSetupState):
    assert isinstance(setup_state.app, flask.Flask)

    config = setup_state.options.get("config", Config())
    if not isinstance(config, Config):
        raise TypeError(
            f"Expected {Config.__qualname__} as `config` option for blueprint, got {type(config)}"
        )

    storage = Storage()

    @setup_state.app.before_request
    def set_storage():
        flask.g.oidc_provider_mock_storage = storage

    def query_client(id: str) -> Client | DummyClient | None:
        client = storage.get_client(id)
        if not client and not config.require_client_registration:
            client = DummyClient(id)
        return client

    def save_token(token: dict[str, object], request: OAuth2Request):
        assert token["token_type"] == "Bearer"
        assert isinstance(token["access_token"], str)
        assert isinstance(request.user, User)
        assert isinstance(token["scope"], str)
        assert isinstance(token["expires_in"], int)

        storage.store_access_token(
            AccessToken(
                token=token["access_token"],
                user_id=request.user.sub,
                scope=token["scope"],
                expires_at=datetime.now(timezone.utc)
                + timedelta(seconds=token["expires_in"]),
            )
        )

    authorization.init_app(  # type: ignore
        setup_state.app,
        query_client=query_client,
        save_token=save_token,
    )

    authorization.register_grant(  # type: ignore
        AuthorizationCodeGrant,
        [
            OpenIDCode(require_nonce=True),
        ],
    )
    authorization.register_grant(ImplicitGrant)  # type: ignore
    authorization.register_grant(HybridGrant)  # type: ignore

    require_oauth.register_token_validator(TokenValidator())


def app(*, require_client_registration: bool = False) -> flask.Flask:
    # TODO: document parameters
    """Create a flask app for the OpenID provider.

    Call :any:`app().run() <flask.Flask.run>` to start the server"""
    app = flask.Flask(__name__)

    app.register_blueprint(
        blueprint,
        config=Config(require_client_registration=require_client_registration),
    )
    return app


@blueprint.get("/")
def home():
    return flask.render_template("index.html")


@blueprint.get("/.well-known/openid-configuration")
def openid_config():
    jwks_uri = flask.url_for(".jwks", _external=True)
    authorization_endpoint = flask.url_for(f".{authorize.__name__}", _external=True)
    token_endpoint = flask.url_for(f".{issue_token.__name__}", _external=True)
    userinfo_endpoint = flask.url_for(f".{userinfo.__name__}", _external=True)

    def url_for(fn: Callable[..., object]) -> str:
        return flask.url_for(f".{fn.__name__}", _external=True)

    return flask.jsonify({
        "issuer": flask.request.host_url.rstrip("/"),
        "authorization_endpoint": authorization_endpoint,
        "token_endpoint": token_endpoint,
        "userinfo_endpoint": userinfo_endpoint,
        "registration_endpoint": url_for(register_client),
        "jwks_uri": jwks_uri,
        "response_types_supported": ["code", "id_token", "id_token token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    })


@blueprint.get("/jwks")
def jwks():
    return flask.jsonify(jose.KeySet((storage.jwk,)).as_dict())  # type: ignore


class RegisterClientRequestPayload(pydantic.BaseModel):
    response_types: Sequence[str]
    redirect_uris: Sequence[pydantic.HttpUrl]


@blueprint.post("/register-client")
def register_client():
    payload = RegisterClientRequestPayload.model_validate(flask.request.json)

    client = Client(
        id=str(uuid4()),
        secret=secrets.token_urlsafe(16),
        redirect_uris=[str(uri) for uri in payload.redirect_uris],
    )
    storage.store_client(client)
    return flask.jsonify({
        "client_id": client.id,
        "client_secret": client.secret,
        "redirect_uris": client.redirect_uris,
    })


@blueprint.route("/oauth2/authorize", methods=["GET", "POST"])
def authorize() -> flask.typing.ResponseReturnValue:
    if flask.request.method == "GET":
        # Validates request parameters
        try:
            authorization.get_consent_grant()  # type: ignore
        except authlib.oauth2.rfc6749.errors.InvalidClientError:
            return "", HTTPStatus.BAD_REQUEST

        return flask.render_template("authorization_form.html")
    else:
        # TODO: validate sub
        user = storage.get_user(flask.request.form["sub"])
        if not user:
            user = User(sub=flask.request.form["sub"])
            storage.store_user(user)
        return authorization.create_authorization_response(grant_user=user)  # type: ignore


@blueprint.route("/oauth2/token", methods=["POST"])
def issue_token() -> flask.typing.ResponseReturnValue:
    # def issue_token():
    return authorization.create_token_response()  # type: ignore


@blueprint.route("/oauth/userinfo", methods=["GET", "POST"])
@require_oauth("profile")
def userinfo():
    return flask.jsonify({
        **current_token.get_user().userinfo,
        "sub": current_token.user_id,
    })


class UserCreatePayload(pydantic.BaseModel):
    claims: dict[str, str] = pydantic.Field(default_factory=dict)
    userinfo: dict[str, object] = pydantic.Field(default_factory=dict)


@blueprint.route("/users/<sub>", methods=["PUT"])
def set_user(sub: str):
    payload = UserCreatePayload.model_validate(flask.request.json, strict=True)
    storage.store_user(User(sub=sub, claims=payload.claims, userinfo=payload.userinfo))
    return "", HTTPStatus.NO_CONTENT
