"""Tests authentication flow only using the POST requests to the authorization
endopint.
"""

from http import HTTPStatus
from typing import Any

import httpx
import oic
import oic.oic
import oic.oic.message
import pytest
from faker import Faker

from .conftest import with_server
from .test_oidc_client import AuthorizationError, OidcClient

faker = Faker()


@with_server(require_client_registration=True)
def test_auth_success(wsgi_server: str):
    """Authorization Code flow success with client registration"""

    subject = faker.email()
    state = faker.password()
    nonce = faker.password()
    redirect_uri = faker.uri(schemes=["https"])

    client = OidcClient.register(wsgi_server, redirect_uri=redirect_uri)

    response = httpx.post(
        client.build_authorization_request(state=state, nonce=nonce),
        data={"sub": subject},
    )
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith(redirect_uri)
    response = client.fetch_token(location, state=state)

    assert isinstance(response, oic.oic.message.AccessTokenResponse)
    assert response["id_token"]["sub"] == subject
    assert response["id_token"]["nonce"] == nonce

    userinfo = client.fetch_userinfo(token=response["access_token"])
    assert userinfo["sub"] == subject


def test_custom_claims(wsgi_server: str):
    """Authenticate with additional claims in ID token and user info"""

    subject = faker.email()
    state = faker.password()

    httpx.put(
        f"{wsgi_server}/users/{subject}",
        json={"custom": "CLAIM"},
    ).raise_for_status()

    client = OidcClient(wsgi_server)

    response = httpx.post(
        client.build_authorization_request(state=state),
        data={"sub": subject},
    )

    response = client.fetch_token(response.headers["location"], state=state)
    assert isinstance(response, oic.oic.message.AccessTokenResponse)
    assert response["id_token"]["sub"] == subject
    assert response["id_token"]["custom"] == "CLAIM"

    userinfo = client.fetch_userinfo(token=response["access_token"])
    assert userinfo["sub"] == subject
    assert userinfo["custom"] == "CLAIM"


def test_include_all_claims(wsgi_server: str):
    subject = faker.email()
    state = faker.password()
    claims: dict[str, Any] = {
        # profile scope
        "name": faker.name(),
        "website": faker.uri(),
        # email scope
        "email": faker.email(),
        # address scope
        "address": {
            "formatted": faker.address(),
        },
        # phone scope
        "phone": faker.phone_number(),
    }

    httpx.put(f"{wsgi_server}/users/{subject}", json=claims).raise_for_status()

    client = OidcClient(wsgi_server)

    response = httpx.post(
        client.build_authorization_request(
            state=state,
            scope="openid profile email address phone",
        ),
        data={"sub": subject},
    )

    response = client.fetch_token(response.headers["location"], state=state)
    assert isinstance(response, oic.oic.message.AccessTokenResponse)
    id_token = response["id_token"]
    assert id_token["sub"] == subject
    assert id_token["name"] == claims["name"]
    assert id_token["website"] == claims["website"]
    assert id_token["email"] == claims["email"]
    assert id_token["address"]["formatted"] == claims["address"]["formatted"]
    assert id_token["phone"] == claims["phone"]

    user_info = client.fetch_userinfo(token=response["access_token"])
    assert user_info["sub"] == subject
    assert user_info["name"] == claims["name"]
    assert user_info["website"] == claims["website"]
    assert user_info["email"] == claims["email"]
    assert user_info["address"]["formatted"] == claims["address"]["formatted"]
    assert user_info["phone"] == claims["phone"]


def test_auth_denied(wsgi_server: str):
    state = faker.password()

    client = OidcClient(wsgi_server)

    response = httpx.post(
        client.build_authorization_request(state=faker.password()),
        data={"action": "deny"},
    )

    with pytest.raises(AuthorizationError, match=r"access_denied"):
        client.fetch_token(response.headers["location"], state=state)


@with_server(require_client_registration=True)
def test_client_not_registered(wsgi_server: str):
    state = faker.password()

    client = OidcClient(wsgi_server)

    response = httpx.post(
        client.build_authorization_request(state=state),
        data={"sub": faker.email()},
    )

    # TODO: Render an HTML error
    # auth error response redirect.
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "Error: invalid_client" in response.text
    assert "Invalid client_id query parameter" in response.text


def test_wrong_client_secret(wsgi_server: str):
    state = faker.password()
    redirect_uri = faker.uri(schemes=["https"])

    client = OidcClient.register(wsgi_server, redirect_uri=redirect_uri)

    # Create a second client with the same ID but different secret
    client = OidcClient(wsgi_server, id=client.id, redirect_uri=redirect_uri)

    response = httpx.post(
        client.build_authorization_request(state=state),
        data={"sub": faker.email()},
    )

    response = client.fetch_token(response.headers["location"], state=state)
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

    client = OidcClient(wsgi_server, auth_method=auth_method)
    auth_url = client.build_authorization_request(state=state)
    response = httpx.post(auth_url, data={"sub": subject})

    response = client.fetch_token(response.headers["location"], state)
    assert response["id_token"]["sub"] == subject

    userinfo = client.fetch_userinfo(token=response["access_token"])
    assert userinfo["sub"] == subject


def test_auth_methods_not_supported_for_client(wsgi_server: str):
    state = faker.password()

    client = OidcClient.register(wsgi_server, auth_method="client_secret_basic")
    auth_url = client.build_authorization_request(state=state)
    response = httpx.post(auth_url, data={"sub": faker.email()})
    response = client.fetch_token(
        response.headers["location"], state=state, auth_method="client_secret_post"
    )
    assert isinstance(response, oic.oic.message.TokenErrorResponse)
    assert dict(response) == {
        "error": "invalid_client",
        "state": state,
    }


@with_server(require_nonce=True)
def test_nonce_required_error(wsgi_server: str):
    state = faker.password()

    client = OidcClient(wsgi_server)
    auth_url = client.build_authorization_request(state=state)
    response = httpx.post(auth_url, data={"sub": faker.email()})
    with pytest.raises(
        AuthorizationError,
        match='Authorization failed: invalid_request: Missing "nonce" in request',
    ):
        client.fetch_token(response.headers["location"], state=state)

    nonce = faker.password()
    auth_url = client.build_authorization_request(state=state, nonce=nonce)
    response = httpx.post(auth_url, data={"sub": faker.email()})
    response = client.fetch_token(response.headers["location"], state=state)
    assert response["id_token"]["nonce"] == nonce


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
