# pyright: basic
"""Tests using pyoidc as the client"""

from urllib.parse import urlsplit

import httpx
import oic
import oic.oic
import oic.oic.message
from faker import Faker
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

faker = Faker()


def test_auth_success(wsgi_server: str):
    """
    Authorization Code flow success using `pyoidc`
    """

    subject = faker.email()
    client_id = faker.pystr(10, 30)
    state = faker.password()
    nonce = faker.password()

    httpx.patch(
        f"{wsgi_server}/users/{subject}",
        json={
            "claims": {"custom": "CLAIM"},
            "userinfo": {"custom": "USERINFO"},
        },
    ).raise_for_status()

    client = oic.oic.Client(client_id, client_authn_method=CLIENT_AUTHN_METHOD)
    client.provider_config(wsgi_server)
    login_url = client.construct_AuthorizationRequest(
        request_args={
            "response_type": "code",
            "scope": ["openid"],
            "nonce": nonce,
            "redirect_uri": "https://example.com/auth-response",
            "state": state,
        }
    ).request(client.authorization_endpoint)

    response = httpx.post(login_url, data={"sub": subject})

    assert response.status_code == 302
    location = urlsplit(response.headers["location"])
    assert location.geturl().startswith("https://example.com/auth-response?")
    authorization_response = client.parse_response(
        oic.oic.message.AuthorizationResponse, info=location.query, sformat="urlencoded"
    )

    assert authorization_response["state"] == state

    response = client.do_access_token_request(
        state=state,
        request_args={"code": authorization_response["code"]},
        authn_method="client_secret_basic",
    )
    assert response["id_token"]["sub"] == subject
    assert response["id_token"]["custom"] == "CLAIM"
    userinfo = client.do_user_info_request(token=response["access_token"])
    assert userinfo["custom"] == "USERINFO"
