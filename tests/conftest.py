import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TypeVar

import flask
import pytest
import typeguard
import werkzeug.serving
from playwright.sync_api import Page

from oidc_provider_mock._app import Config

typeguard.install_import_hook("oidc_provider_mock")
import oidc_provider_mock  # noqa: E402


@pytest.fixture
def app():
    app = oidc_provider_mock.app()
    # Use localhost with port so that https is not required
    app.config["SERVER_NAME"] = "localhost:54321"
    return app


@pytest.fixture
def wsgi_server(request: pytest.FixtureRequest) -> Iterator[str]:
    param = getattr(request, "param", None)
    if param:
        config = Config(param)
        run = oidc_provider_mock.run_server_in_thread(**config)
    else:
        run = oidc_provider_mock.run_server_in_thread()

    with run as server:
        yield f"http://localhost:{server.server_port}"


_C = TypeVar("_C", bound=Callable[..., None])


def use_provider_config(
    *,
    require_client_registration: bool = False,
    require_nonce: bool = False,
    issue_refresh_token: bool = True,
) -> Callable[[_C], _C]:
    """Set configuration for the app under test."""
    return pytest.mark.parametrize(
        "wsgi_server",
        [
            Config(
                require_client_registration=require_client_registration,
                require_nonce=require_nonce,
                issue_refresh_token=issue_refresh_token,
            ),
        ],
        indirect=True,
        ids=[""],
    )


@pytest.fixture
def page(page: Page):
    page.set_default_navigation_timeout(3000)
    page.set_default_timeout(3000)
    return page


@dataclass
class LiveServer:
    app: flask.Flask
    server: werkzeug.serving.BaseWSGIServer

    def url(self, path: str):
        path = path.lstrip("/")
        return f"http://localhost:{self.server.server_port}/{path}"


@contextmanager
def live_server(app: flask.Flask) -> Iterator[LiveServer]:
    server = werkzeug.serving.make_server(
        "localhost",
        0,
        app,
        threaded=True,
    )

    def run():
        try:
            server.serve_forever(0.01)
        finally:
            server.server_close()

    server_thread = threading.Thread(target=run)
    server_thread.start()

    app.config["SERVER_NAME"] = f"localhost:{server.server_port}"

    try:
        yield LiveServer(app, server)

    finally:
        shutdown_thread = threading.Thread(target=server.shutdown)
        shutdown_thread.start()
        shutdown_thread.join(1)
        if shutdown_thread.is_alive():
            raise TimeoutError("Server failed to shut down in time")

        server_thread.join(0.5)
        if server_thread.is_alive():
            raise TimeoutError("Server thread timed out")
