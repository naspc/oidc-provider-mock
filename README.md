# OpenID Provider Mock

> A mock OpenID Provider server to test and develop OpenID Connect
> authentication.

## Usage

Run the OpenID Provider server

```bash
$ pipx run oidc-provider-mock
Started OpenID provider http://localhost:9400
```

(TODO: package is not published yet)

Configure the OpenID Connect client library in your app to use
`http://localhost:9400` as the issuer URL.

Now you can authenticate and authorize the app in the login form.

(TODO: create video)

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
