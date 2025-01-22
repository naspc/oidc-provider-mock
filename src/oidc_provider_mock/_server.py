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
    port: int = 0,
    *,
    require_client_registration: bool = False,
    require_nonce: bool = False,
) -> Iterator[WSGIServer]:
    """Run a OIDC provider server on a background thread.

    The server is stopped when the context ends. This function uses
    :any:`wsgiref.simple_server.WSGIServer` which has some limitations.

    See `oidc_provider_mock.app` for documentation of parameters.

    >>> with run_server_in_thread(port=35432) as server:
    ...     print(f"Server listening at http://localhost:{server.server_port}")
    Server listening at http://localhost:35432
    """
    server = wsgiref.simple_server.make_server(
        "localhost",
        port,
        app(
            require_client_registration=require_client_registration,
            require_nonce=require_nonce,
        ),
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
