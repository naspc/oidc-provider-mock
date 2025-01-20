# pyright: reportUnknownMemberType=none
"""Test OIDC login of a Flask app using
[Flask-OIDC](https://flask-oidc.readthedocs.io/en/stable/).
"""

import logging
from pathlib import Path
from urllib.parse import quote

import flask
import flask.testing
import httpx
import pytest
from flask_oidc import OpenIDConnect

import oidc_provider_mock

app = flask.Flask(__name__)
app.config.update({
    "OIDC_CLIENT_SECRETS": Path(__file__).parent / "flask_oidc_client_secrets.json",
    "SECRET_KEY": "some secret",
})


@app.route("/")
def index():
    user = flask.g.oidc_user
    if user.logged_in:
        return f"Welcome {user.profile['name']} <{user.email}>"
    else:
        return "Not logged in"


@pytest.fixture(name="app")
def app_fixture(oidc_server: str):
    app.config["OIDC_SERVER_METADATA_URL"] = (
        f"{oidc_server}/.well-known/openid-configuration"
    )
    OpenIDConnect(app)
    return app


@pytest.fixture
def oidc_server():
    logging.getLogger("oidc_provider_mock").setLevel(logging.DEBUG)
    with oidc_provider_mock.run_server_in_thread() as server:
        yield f"http://localhost:{server.server_port}"


def test_auth_code_login(client: flask.testing.FlaskClient, oidc_server: str):
    # Let the OIDC provider know about the user’s email and name
    response = httpx.put(
        f"{oidc_server}/users/{quote('alice@example.com')}",
        json={"userinfo": {"email": "alice@example.com", "name": "Alice"}},
    )

    # Start login on the client and get the authorization URL
    response = client.get("/login")
    assert response.location

    # Authorize the client by POSTing to the authorization URL.
    response = httpx.post(response.location, data={"sub": "alice@example.com"})

    # Go back to the client with the authorization code
    assert response.has_redirect_location
    response = client.get(response.headers["location"])

    # Check that we have been authenticated
    assert response.location
    response = client.get(response.location)
    assert response.text == "Welcome Alice <alice@example.com>"


if __name__ == "__main__":
    OpenIDConnect(app)
    app.run(debug=True)
