from urllib.parse import urlsplit

import flask
import flask.testing
import pytest
import requests

import oidc
import oidc_provider_mock


@pytest.fixture
def app():
    app = flask.Flask(__name__)

    state = oidc_provider_mock.State()
    app.register_blueprint(oidc_provider_mock.blueprint, state=state)

    return app


def test_login_success(wsgi_server: str):
    """
    Authorization Code flow success with userinfo
    """

    openid_config = oidc.ProviderConfiguration.fetch(wsgi_server)
    authorization_request = oidc.start_authorization(
        openid_config,
        redirect_uri="https://example.com/auth-response",
        client_id="CLIENT_ID",
    )

    response = requests.post(
        authorization_request.url,
        data={
            "sub": "SUB",
        },
        allow_redirects=False,
    )

    assert response.status_code == 302
    location = urlsplit(response.headers["location"])
    assert location.geturl().startswith("https://example.com/auth-response?")

    authn_result = oidc.authenticate(
        openid_config, authorization_request, location.query
    )
    assert authn_result.claims["sub"] == "SUB"

    assert openid_config.userinfo_endpoint
    response = requests.get(
        openid_config.userinfo_endpoint,
        headers={"authorization": f"Bearer {authn_result.access_token}"},
    )
    response.raise_for_status()
    assert response.json() == {
        "sub": "SUB",
        "email": "SUB",
    }


@pytest.mark.skip
def test_invalid_nonce(): ...


@pytest.mark.skip
def test_custom_claims(): ...


@pytest.mark.skip
def test_custom_claims(): ...
