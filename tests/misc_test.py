import flask.testing


def test_put_user_validation(client: flask.testing.FlaskClient):
    response = client.put(
        "/users/foobar",
        json={
            "claims": {"bar": True},
            "userinfo": True,
            "other": 1,
        },
    )
    assert response.status_code == 400
    assert response.text == (
        "Invalid body:\n"
        "- claims.bar: Input should be a valid string\n"
        "- userinfo: Input should be a valid dictionary\n"
    )
