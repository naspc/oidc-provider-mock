from collections.abc import Iterator
import logging
import threading
import wsgiref.simple_server
import wsgiref.types

import pytest
import pytest_flask.live_server
from playwright.sync_api import BrowserContext, Error, Page


@pytest.fixture
def browser_context_args(
    browser_context_args: dict[str, object],
    live_server: pytest_flask.live_server.LiveServer,
):
    return {**browser_context_args, "base_url": live_server.url()}


@pytest.fixture
def page(context: BrowserContext) -> Page:
    page = context.new_page()

    def on_page_error(error: Error):
        raise Exception("page error occurred") from error

    page.on("pageerror", on_page_error)
    return page


_logger = logging.getLogger(__name__)


class _WSGIRequestHandler(wsgiref.simple_server.WSGIRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        _logger.log(logging.INFO, format % args)


@pytest.fixture
def wsgi_server(
    app: wsgiref.types.WSGIApplication,
) -> Iterator[str]:
    server = wsgiref.simple_server.make_server(
        "localhost", 0, app, handler_class=_WSGIRequestHandler
    )

    def run():
        try:
            server.serve_forever()
        finally:
            server.server_close()

    thread = threading.Thread(target=run)
    thread.start()

    try:
        yield f"http://localhost:{server.server_port}"

    finally:
        server.shutdown()
        thread.join()
