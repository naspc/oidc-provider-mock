# pyright: basic
"""Tests using pyoidc as the client"""

from urllib.parse import urlsplit

import httpx
import oic
import oic.oic
import oic.oic.message
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

    httpx.put(
        f"{wsgi_server}/users/{subject}",
        json={
            "claims": {"custom": "CLAIM"},
            "userinfo": {"custom": "USERINFO"},
        },
    ).raise_for_status()

    client = oic.oic.Client(client_authn_method=CLIENT_AUTHN_METHOD)
    client.redirect_uris = [redirect_uri]
    config = client.provider_config(wsgi_server)
    client.register(config["registration_endpoint"])
    login_url = client.construct_AuthorizationRequest(
        request_args={
            "response_type": "code",
            "scope": ["openid"],
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
        request_args={"code": response["code"]},
        authn_method="client_secret_basic",
    )
    assert isinstance(response, oic.oic.message.AccessTokenResponse)
    assert response["id_token"]["sub"] == subject
    assert response["id_token"]["custom"] == "CLAIM"
    assert response["id_token"]["nonce"] == nonce

    userinfo = client.do_user_info_request(token=response["access_token"])
    assert userinfo["sub"] == subject
    assert userinfo["custom"] == "USERINFO"
