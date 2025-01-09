HTTP Endpoints
==============

``GET /oauth2/authorize``
---------------------

Show an authentication form to the user. Submitting the form will redirect to
the relying party that requested the authentication.

Query parameters:

``client_id`` (required)
  ID of the client that requests authentication

``redirect_uri`` (required)

``repsonse_type`` (required)
  https://openid.net/specs/openid-connect-core-1_0.html#Authentication
