import logging
import threading
import wsgiref.simple_server
from collections.abc import Iterator
from contextlib import contextmanager
from wsgiref.simple_server import WSGIServer

from ._app import app

assert __package__

_server_logger = logging.getLogger(f"{__package__}.server")


class _WSGIRequestHandler(wsgiref.simple_server.WSGIRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        _server_logger.log(logging.INFO, format % args)


@contextmanager
def run_server_in_thread(
    port: int = 0, require_client_registration: bool = False
) -> Iterator[WSGIServer]:
    # TODO: document
    server = wsgiref.simple_server.make_server(
        "localhost",
        port,
        app(),
        handler_class=_WSGIRequestHandler,
    )

    def run():
        try:
            server.serve_forever(0.01)
        finally:
            server.server_close()

    thread = threading.Thread(target=run)
    thread.start()

    try:
        yield server

    finally:
        server.shutdown()
        thread.join()
