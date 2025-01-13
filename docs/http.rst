HTTP Endpoints
==============

``GET /oauth2/authorize``
-------------------------


OpenID Connect `authorization endpoint`_. On a `GET`, show an authentication
form to the user. Submitting the form will redirect to the relying party that
requested the authentication.

Query parameters:

``client_id`` (required)
  ID of the client that requests authentication

``redirect_uri`` (required)
  Redirection URI to which the response will be sent

``response_type`` (required)
  Type of authorization response which also determines the OAuth2.0 flow
  Currently, only ``code`` is supported.

.. _authorization endpoint: https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint



``PATCH /users/{sub}``
----------------------

Set user information to be included in responses in the ID token and the
userinfo endpoint.

The payload is a JSON document of the following shape:

.. code:: json

    {
      "claims": {
          "email": "alice@example.com"
      },
      "userinfo": {
          "avatar_url": "https://example.com/alice.jpg"
      }
    }

Claims and userinfo are merged into existing data from previous requests.
