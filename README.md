# OpenID Provider Mock

> A mock OpenID Provider server to test and develop OpenID Connect
> authentication.

## Usage

Run the OpenID Provider server

```bash
$ pipx run oidc-provider-mock
Started OpenID provider http://localhost:9400
```

Configure the OpenID Connect client library in your app to use
`http://localhost:9400` as the issuer URL. You can use any client ID and client
secret with the provider.

Now you can authenticate and authorize the app in the login form.

Take a look at the following example for using the server in a test.

```python
@pytest.fixture
def oidc_server():
    logging.getLogger("oidc_provider_mock.server").setLevel(logging.DEBUG)
    with oidc_provider_mock.run_server_in_thread() as server:
        yield f"http://localhost:{server.server_port}"


def test_login(client: flask.testing.FlaskClient, oidc_server: str):
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
```

For all full testing example, see
[`examples/flask_oidc_example.py`](../examples/flask_oidc_example.py)


## Alternatives

There already exist a couple of OpendID provider servers for testing. This is
how they differ from this project (to the best of my knowledge):

[`axa-group/oauth2-mock-server`](https://github.com/axa-group/oauth2-mock-server)

* Does not offer a HTML login form where the subject can be input or
  authorization denied.
* Behavior can only be customized through the JavaScript API.

[`Soluto/oidc-server-mock`](https://github.com/Soluto/oidc-server-mock)

* Identities (users) and clients must be statically configured.
* Requires a non-trivial amount of configuration before it can be used.

[`oauth2-proxy/mockoidc`](https://github.com/oauth2-proxy/mockoidc`)

* Does not have a CLI, only available as a Go library

<https://oauth.wiremockapi.cloud/>

* Only a hosted version exists
* Claims and user info cannot be customized
* Cannot simulate errors
