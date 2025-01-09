import flask

from . import _internal


def app() -> flask.Flask:
    """Create a flask app for the OpenID provider.

    Call :any:`app().run() <flask.Flask.run>` to start the server"""
    app = flask.Flask(__name__)

    state = _internal.State()
    app.register_blueprint(_internal.blueprint, state=state)
    return app
