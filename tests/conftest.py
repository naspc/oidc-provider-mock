import functools
from collections.abc import Callable, Iterator

import pytest
import typeguard

typeguard.install_import_hook("oidc_provider_mock")
import oidc_provider_mock  # noqa: E402


@pytest.fixture
def app():
    app = oidc_provider_mock.app()
    # Use localhost with port so that https is not required
    app.config["SERVER_NAME"] = "localhost:54321"
    return app


@pytest.fixture
def wsgi_server() -> Iterator[str]:
    with oidc_provider_mock.run_server_in_thread() as server:
        yield f"http://localhost:{server.server_port}"


def with_server(
    require_client_registration: bool = False, require_nonce: bool = False
) -> Callable[
    [Callable[[str], None]],
    Callable[[], None],
]:
    def decorate(test_fn: Callable[[str], None]) -> Callable[[], None]:
        @functools.wraps(test_fn)
        def wrapped_test_fn():
            with oidc_provider_mock.run_server_in_thread(
                require_client_registration=require_client_registration,
                require_nonce=require_nonce,
            ) as server:
                test_fn(f"http://localhost:{server.server_port}")

        # Prevent pytest from considering argument to the original test function
        # as a fixture.
        del wrapped_test_fn.__wrapped__
        return wrapped_test_fn

    return decorate
