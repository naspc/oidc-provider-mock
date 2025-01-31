from collections.abc import Callable, Iterator
from typing import TypeVar

import pytest
import typeguard

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
) -> Callable[[_C], _C]:
    """Set configuration for the app under test."""
    return pytest.mark.parametrize(
        "wsgi_server",
        [
            Config(
                require_client_registration=require_client_registration,
                require_nonce=require_nonce,
            ),
        ],
        indirect=True,
        ids=[None],
    )
