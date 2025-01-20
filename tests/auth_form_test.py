from http import HTTPStatus
from urllib.parse import urlencode

import flask.testing
import pytest
from faker import Faker

import oidc_provider_mock

faker = Faker()


@pytest.fixture
def app():
    app = oidc_provider_mock.app(require_client_registration=True)
    # Use localhost with port so that https is not required
    app.config["SERVER_NAME"] = "localhost:54321"
    return app


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


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_invalid_client(client: flask.testing.FlaskClient, method: str):
    """
    Respond with 400 and error description when:

    * client_id query parameter is missing
    * client unknown
    * redirect_uri does not match the URI that was registered
    """

    query = urlencode({
        "redirect_uri": "foo",
        "response_type": "code",
    })
    response = client.open(f"/oauth2/authorize?{query}", method=method)
    assert response.status_code == 400
    assert "Error: invalid_client" in response.text
    # TODO improve error message: tell user that is missing
    assert "Invalid client_id query parameter" in response.text

    query = urlencode({
        "client_id": "UNKNOWN",
        "redirect_uri": "foo",
        "response_type": "code",
    })
    response = client.open(f"/oauth2/authorize?{query}", method=method)
    assert response.status_code == 400
    assert "Error: invalid_client" in response.text
    # TODO improve error message
    assert "Invalid client_id query parameter" in response.text

    redirect_uris = [faker.uri(schemes=["https"])]
    response = client.post(
        "/register-client",
        json={
            "redirect_uris": redirect_uris,
        },
    )
    assert response.status_code == HTTPStatus.CREATED
    oidc_client = response.json
    assert oidc_client

    query = urlencode({
        "client_id": oidc_client["client_id"],
        "redirect_uri": "foo",
        "response_type": "code",
    })
    response = client.open(f"/oauth2/authorize?{query}", method=method)
    assert response.status_code == 400
    assert "Error: invalid_client" in response.text
    assert "Redirect URI foo is not supported by client." in response.text


@pytest.mark.skip
def test_refresh(): ...
