from urllib.parse import urlencode, urlsplit

import flask.testing
import httpx
import oidc_client
import pytest
from faker import Faker

faker = Faker()


def test_auth_success(wsgi_server: str):
    """
    Authorization Code flow success with userinfo
    """

    subject = faker.email()
    client_id = faker.pystr(10, 30)

    httpx.patch(
        f"{wsgi_server}/users/{subject}",
        json={
            "claims": {"custom": "CLAIM"},
            "userinfo": {"custom": "USERINFO"},
        },
    ).raise_for_status()

    openid_config = oidc_client.ProviderConfiguration.fetch(wsgi_server)
    authorization_request = oidc_client.start_authorization(
        openid_config,
        redirect_uri="https://example.com/auth-response",
        client_id=client_id,
    )

    response = httpx.post(
        authorization_request.url,
        data={
            "sub": subject,
        },
    )

    assert response.status_code == 302
    location = urlsplit(response.headers["location"])
    assert location.geturl().startswith("https://example.com/auth-response?")

    authentication_result = oidc_client.get_token(
        openid_config, authorization_request, location.query
    )
    assert authentication_result.claims["sub"] == subject
    assert authentication_result.claims["custom"] == "CLAIM"

    assert openid_config.userinfo_endpoint
    response = httpx.get(
        openid_config.userinfo_endpoint,
        headers={"authorization": f"Bearer {authentication_result.access_token}"},
    )
    response.raise_for_status()
    assert response.json() == {
        "custom": "USERINFO",
    }


@pytest.mark.skip
def test_authorize_deny():
    """User denies auth via form and is redirected with an error response"""


def test_authorization_form_show(client: flask.testing.FlaskClient):
    # TODO: test html form
    query = urlencode({
        "client_id": "CLIENT_ID",
        "redirect_uri": "REDIRECT_URI",
        "response_type": "code foo",
    })
    response = client.get(f"/oauth2/authorize?{query}")
    assert response.status_code == 200


@pytest.mark.xfail
def test_authorization_query_parsing(client: flask.testing.FlaskClient):
    """
    * client_id missing
    * invalid redirect_uri
    * invalid response_type

    All return a 400 with error description
    """
    query = urlencode({
        "redirect_uri": "REDIRECT_URI",
        "response_type": "RESPONSE_TYPE",
    })
    response = client.get(f"/oauth2/authorize?{query}")
    assert response.status_code == 400
    assert "client_id missing from query parameters" in response.text

    # TODO: invalid redirect_uri
    query = urlencode({
        "client_id": "CLIENT_ID",
        "redirect_uri": "invalid url",
        "response_type": "RESPONSE_TYPE",
    })
    response = client.get(f"/oauth2/authorize?{query}")
    assert response.status_code == 400
    assert "redirect_uri missing from query parameters" in response.text

    query = urlencode({
        "client_id": "CLIENT_ID",
        "redirect_uri": "REDIRECT_URI",
        "response_type": "unknown",
    })
    response = client.get(f"/oauth2/authorize?{query}")
    assert response.status_code == 400
    assert "invalid response_type" in response.text


@pytest.mark.skip
def test_userinfo_unauthorized():
    """
    * `authorization` header missing
    * `authorization` with wrong type
    * `authorization` with invalid token

    All return 400 error with description
    """


@pytest.mark.skip
def test_refresh(): ...


@pytest.mark.skip
def test_invalid_nonce(): ...


@pytest.mark.skip
def test_custom_claims(): ...
