# pyright: basic
"""Tests using pyoidc as the client"""

from http import HTTPStatus
from urllib.parse import urlsplit

import httpx
import oic
import oic.oic
import oic.oic.message
import pytest
from conftest import with_server
from faker import Faker
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

faker = Faker()


@with_server(require_client_registration=True)
def test_auth_success(wsgi_server: str):
    """Authorization Code flow success with client registration"""

    subject = faker.email()
    state = faker.password()
    nonce = faker.password()
    redirect_uri = faker.uri(schemes=["https"])

    client = oic.oic.Client(client_authn_method=CLIENT_AUTHN_METHOD)
    client.redirect_uris = [redirect_uri]
    config = client.provider_config(wsgi_server)
    client.register(config["registration_endpoint"])
    login_url = client.construct_AuthorizationRequest(
        request_args={
            "nonce": nonce,
            "state": state,
        }
    ).request(client.authorization_endpoint)

    response = httpx.post(login_url, data={"sub": subject})

    assert response.status_code == 302
    location = urlsplit(response.headers["location"])
    assert location.geturl().startswith(redirect_uri)
    response = client.parse_response(
        oic.oic.message.AuthorizationResponse, info=location.query, sformat="urlencoded"
    )

    assert isinstance(response, oic.oic.message.AuthorizationResponse)
    assert response["state"] == state

    response = client.do_access_token_request(
        state=state,
        code=response["code"],
    )
    assert isinstance(response, oic.oic.message.AccessTokenResponse)
    assert response["id_token"]["sub"] == subject
    assert response["id_token"]["nonce"] == nonce

    userinfo = client.do_user_info_request(token=response["access_token"])
    assert userinfo["sub"] == subject


def test_custom_claims_and_userinfo(wsgi_server: str):
    """Authenticate with additional claims and userinfo"""

    subject = faker.email()
    state = faker.password()

    httpx.put(
        f"{wsgi_server}/users/{subject}",
        json={
            "claims": {"custom": "CLAIM"},
            "userinfo": {"custom": "USERINFO"},
        },
    ).raise_for_status()

    client = oic.oic.Client(client_authn_method=CLIENT_AUTHN_METHOD)
    client.provider_config(wsgi_server)
    client.store_registration_info({
        "client_id": faker.uuid4(),
        "client_secret": faker.password(),
    })
    login_url = client.construct_AuthorizationRequest(
        request_args={
            "scope": "openid email",
            "redirect_uri": faker.uri(schemes=["https"]),
            "response_type": "code",
            "state": state,
        }
    ).request(client.authorization_endpoint)

    response = httpx.post(login_url, data={"sub": subject})

    location = urlsplit(response.headers["location"])
    response = client.parse_response(
        oic.oic.message.AuthorizationResponse, info=location.query, sformat="urlencoded"
    )
    assert isinstance(response, oic.oic.message.AuthorizationResponse)
    response = client.do_access_token_request(
        state=state,
        code=response["code"],
    )

    assert isinstance(response, oic.oic.message.AccessTokenResponse)
    assert response["id_token"]["sub"] == subject
    assert response["id_token"]["custom"] == "CLAIM"

    userinfo = client.do_user_info_request(token=response["access_token"])
    assert userinfo["sub"] == subject
    assert userinfo["custom"] == "USERINFO"


@with_server(require_client_registration=True)
def test_client_not_registered(wsgi_server: str):
    state = faker.password()

    client = oic.oic.Client(client_authn_method=CLIENT_AUTHN_METHOD)
    client.redirect_uris = [faker.uri(schemes=["https"])]
    client.provider_config(wsgi_server)
    login_url = client.construct_AuthorizationRequest(
        request_args={
            "response_type": "code",
            "state": state,
        }
    ).request(client.authorization_endpoint)

    response = httpx.post(login_url, data={"sub": faker.email()})
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.json() == {
        "error": "invalid_client",
        "state": state,
    }


def test_wrong_client_secret(wsgi_server: str):
    state = faker.password()
    redirect_uri = faker.uri(schemes=["https"])

    client = oic.oic.Client(client_authn_method=CLIENT_AUTHN_METHOD)
    client.redirect_uris = [redirect_uri]
    config = client.provider_config(wsgi_server)
    client.register(config["registration_endpoint"])
    client.client_secret = "foo"

    login_url = client.construct_AuthorizationRequest(
        request_args={
            "response_type": "code",
            "state": state,
        }
    ).request(client.authorization_endpoint)

    response = httpx.post(login_url, data={"sub": faker.email()})

    location = urlsplit(response.headers["location"])
    response = client.parse_response(
        oic.oic.message.AuthorizationResponse, info=location.query, sformat="urlencoded"
    )

    response = client.do_access_token_request(
        state=state,
        code=response["code"],
        client_secret="foo",
    )
    assert isinstance(response, oic.oic.message.TokenErrorResponse)
    assert dict(response) == {
        "error": "invalid_client",
        "state": state,
    }


@pytest.mark.parametrize(
    "auth_method",
    [
        "client_secret_basic",
        "client_secret_post",
    ],
)
def test_client_auth_methods(wsgi_server: str, auth_method: str):
    subject = faker.email()
    state = faker.password()

    client = OidcClient(wsgi_server)
    client.register()
    auth_url = client.build_authorization_request(state=state)
    response = httpx.post(auth_url, data={"sub": subject})
    response = client.fetch_token(response.headers["location"], state)

    assert response["id_token"]["sub"] == subject

    userinfo = client.fetch_userinfo(token=response["access_token"])
    assert userinfo["sub"] == subject


def test_no_openid_scope(wsgi_server: str):
    subject = faker.email()
    state = faker.password()

    client = OidcClient(wsgi_server)

    response = httpx.post(
        client.build_authorization_request(state=state, scope="foo bar"),
        data={"sub": subject},
    )

    response = client.fetch_token(response.headers["location"], state)
    assert response["token_type"] == "Bearer"
    assert "id_token" not in response


class OidcClient:
    _oic_client: oic.oic.Client

    def __init__(self, issuer: str) -> None:
        self._oic_client = oic.oic.Client(client_authn_method=CLIENT_AUTHN_METHOD)
        self._oic_client.provider_config(issuer)

        self._oic_client.store_registration_info({
            "client_id": faker.uuid4(),
            "client_secret": faker.password(),
        })
        self._oic_client.redirect_uris = [faker.uri(schemes=["https"])]

    def register(self):
        self._oic_client.register(self._oic_client.registration_endpoint)  # type: ignore

    def build_authorization_request(
        self, *, state: str, scope: str = "openid", response_type: str = "code"
    ):
        return self._oic_client.construct_AuthorizationRequest(
            request_args={
                "response_type": response_type,
                "state": state,
                "scope": scope,
            }
        ).request(self._oic_client.authorization_endpoint)

    def fetch_token(self, auth_response_location: str, state: str):
        location = urlsplit(auth_response_location)
        response = self._oic_client.parse_response(
            oic.oic.message.AuthorizationResponse,
            info=location.query,
            sformat="urlencoded",
        )
        response = self._oic_client.do_access_token_request(
            state=state,
            code=response["code"],
        )

        assert isinstance(
            response,
            oic.oic.message.AccessTokenResponse | oic.oic.message.TokenErrorResponse,
        )

        return response

    def fetch_userinfo(self, token: str):
        return self._oic_client.do_user_info_request(token=token)
