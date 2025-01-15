from http import HTTPStatus
from urllib.parse import urlencode

import flask.testing
import pytest
from faker import Faker

faker = Faker()


def test_authorize_deny():
    """User denies auth via form and is redirected with an error response"""


@pytest.mark.xfail
def test_authorization_form_show(client: flask.testing.FlaskClient):
    # TODO: test html form
    query = urlencode({
        "client_id": "CLIENT_ID",
        "redirect_uri": "REDIRECT_URI",
        "response_type": "code",
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
        "response_type": "code",
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


def test_userinfo_unauthorized(client: flask.testing.FlaskClient):
    response = client.get("/userinfo")
    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.www_authenticate.type == "bearer"
    assert response.json
    assert response.json["error"] == "missing_authorization"

    response = client.get("/userinfo", headers={"authorization": "foo"})
    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.json == {"error": "unsupported_token_type"}

    response = client.get("/userinfo", headers={"authorization": "Bearer foo"})
    # TODO: should be unauthorized
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.json
    assert response.json["error"] == "access_denied"


@pytest.mark.skip
def test_refresh(): ...
