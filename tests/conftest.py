import logging
import threading
import wsgiref.simple_server
import wsgiref.types
from collections.abc import Iterator

import pytest

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
