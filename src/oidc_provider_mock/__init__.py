import functools
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode, urlsplit

import flask
import werkzeug.exceptions
from authlib import jose


class _AccessToken:
    def __init__(self, email: str, expires_in: timedelta):
        self.email = email
        self.expires_at = datetime.now(UTC) + expires_in
        self.token = secrets.token_urlsafe(16)


@dataclass(kw_only=True)
class _AuthorizationGrant:
    sub: str
    nonce: str | None
    client_id: str
    code: str = field(init=False)
    expires_at: datetime = field(init=False)

    def __post_init__(self):
        # TODO: allow configuration of expiration
        self.expires_at = datetime.now(UTC) + timedelta(seconds=60)
        self.code = secrets.token_urlsafe(16)

    def valid(self) -> bool:
        return self.expires_at > datetime.now(UTC)


class State:
    _access_tokens: list[_AccessToken]
    _authorization_grants: list[_AuthorizationGrant]

    def __init__(
        self,
        issuer: str = "https://oauth2.example.com",
        access_token_lifetime: timedelta = timedelta(hours=1),
    ) -> None:
        self._access_tokens_lifetime = access_token_lifetime
        # TODO: limit number of items
        self._access_tokens = []
        self._authorization_grants = []
        self.issuer = issuer
        self.key = jose.RSAKey.generate_key(2048, is_private=True)  # pyright: ignore[reportUnknownMemberType]

    def get_access_token(self, token: str) -> _AccessToken | None:
        return next(
            (identity for identity in self._access_tokens if identity.token == token),
            None,
        )

    def get_authorization(self, code: str) -> _AuthorizationGrant | None:
        authorization_grant = next(
            (a for a in self._authorization_grants if a.code == code),
            None,
        )

        if not authorization_grant:
            return None

        if not authorization_grant.valid():
            self._authorization_grants.remove(authorization_grant)
            return None

        return authorization_grant

    def add_authorization_grant(self, grant: _AuthorizationGrant):
        self._authorization_grants.append(grant)

    def add_access_token(
        self, user_email: str, expires_in: timedelta | None = None
    ) -> _AccessToken:
        identity = _AccessToken(user_email, expires_in or self._access_tokens_lifetime)
        self._access_tokens.append(identity)
        return identity

    @staticmethod
    def current() -> "State":
        return flask.g.oidc_mock_provider_state

    def bind_to_app_context(self, app: flask.Flask):
        @app.before_request
        def provide_state():
            flask.g.oidc_mock_provider_state = self


blueprint = flask.Blueprint("oidc-provider", __name__)


@blueprint.record
def bind_state_to_app_context(setup_state: flask.blueprints.BlueprintSetupState):
    assert isinstance(setup_state.app, flask.Flask)
    state = setup_state.options["state"]
    if not isinstance(state, State):
        raise TypeError("Blueprint option `state` must be an instance of `State`")
    state.bind_to_app_context(setup_state.app)


@blueprint.get("/.well-known/openid-configuration")
def openid_config():
    jwks_uri = flask.url_for(".jwks", _external=True)
    authorization_endpoint = flask.url_for(f".{authorize.__name__}", _external=True)
    token_endpoint = flask.url_for(".get_token", _external=True)
    userinfo_endpoint = flask.url_for(".userinfo", _external=True)
    return flask.jsonify({
        "issuer": State.current().issuer,
        "authorization_endpoint": authorization_endpoint,
        "token_endpoint": token_endpoint,
        "userinfo_endpoint": userinfo_endpoint,
        "jwks_uri": jwks_uri,
        "response_types_supported": ["code", "id_token", "id_token token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    })


@blueprint.get("/jwks")
def jwks():
    return flask.jsonify(jose.KeySet((State.current().key,)).as_dict())  # type: ignore


def show_bad_request_details[**T, R](fn: Callable[T, R]) -> Callable[T, R]:
    @functools.wraps(fn)
    def wrapped(*args: T.args, **kwargs: T.kwargs):
        try:
            return fn(*args, **kwargs)
        except werkzeug.exceptions.BadRequestKeyError as ex:
            ex.show_exception = True
            raise ex

    return wrapped


@blueprint.route("/oauth2/authorize", methods=("GET", "POST"))
@show_bad_request_details
def authorize():
    if flask.request.method == "GET":
        return ask_authorization()
    else:
        return process_authorization()


def ask_authorization():
    query = flask.request.args
    # TODO: verify client_id matches redirect uri
    for name in {"client_id", "redirect_uri", "response_type"}:
        if name not in query:
            raise werkzeug.exceptions.BadRequest(
                f"{name} missing from query parameters"
            )

    return (
        '<form method="post">'
        '<input type="text" name="sub" placeholder="sub">'
        '<button type="submit">Authorize</button>'
        "</form>"
        '<form method="post">'
        '<button type="submit" name="action" value="deny_access">Deny</button>'
        "</form>"
    )


def process_authorization():
    query = flask.request.args
    redirect_uri = urlsplit(query["redirect_uri"])
    # TODO: ensure redirection only to localhost

    if flask.request.form.get("action") == "deny_access":
        return flask.redirect(
            redirect_uri._replace(query=urlencode({"error": "access_denied"})).geturl()
        )

    nonce = query.get("nonce", None)
    client_id = query["client_id"]

    authorization_grant = _AuthorizationGrant(
        sub=flask.request.form["sub"],
        nonce=nonce,
        client_id=client_id,
    )
    State.current().add_authorization_grant(authorization_grant)

    return flask.redirect(
        redirect_uri._replace(
            query=urlencode({
                "state": query["state"],
                "code": authorization_grant.code,
            })
        ).geturl()
    )


@blueprint.post("/oauth2/token")
@show_bad_request_details
def get_token():
    data = flask.request.form
    # TODO: params grant_type, redirect_uri, client_id
    # TODO: client auth
    authorization = State.current().get_authorization(data["code"])
    if not authorization:
        return flask.jsonify({"error": "invalid_grant"}), 404

    identity = State.current().add_access_token(authorization.sub)
    id_token = jose.jwt.encode(  # pyright: ignore
        {
            "alg": "RS256",
            "kid": State.current().key.thumbprint(),
        },
        {
            "iss": State.current().issuer,
            "aud": authorization.client_id,
            "sub": authorization.sub,
            "nonce": authorization.nonce,
            "iat": datetime.now(UTC).timestamp(),
            # TODO: allow configuration of expiration
            "exp": (datetime.now(UTC) + timedelta(hours=1)).timestamp(),
        },
        State.current().key,
    ).decode("utf-8")

    return (
        flask.jsonify({
            "access_token": identity.token,
            "token_type": "Bearer",
            "expires_in": 3600,
            # "refresh_token": "REFRESH_TOKEN",
            "id_token": id_token,
        }),
        200,
        {"cache-control": "no"},
    )


@blueprint.get("/userinfo")
def userinfo():
    if (
        not flask.request.authorization
        or flask.request.authorization.type != "bearer"
        or not flask.request.authorization.token
    ):
        return b"", 401, {"www-authenticate": "Bearer", "cache-control": "no"}
    identity = State.current().get_access_token(flask.request.authorization.token)
    if not identity:
        return b"", 401, {"www-authenticate": "Bearer", "cache-control": "no"}

    return (
        flask.jsonify({"sub": identity.email, "email": identity.email}),
        200,
        {"cache-control": "no"},
    )
