from datetime import timedelta

import click
import uvicorn

from . import app
from ._app import Config

_default_config = Config


@click.command(context_settings={"max_content_width": 100})
@click.option(
    "-p",
    "--port",
    help="Port to start server on",
    default=9400,
    show_default=True,
)
@click.option(
    "-r",
    "--require-registration",
    help="Require client to register before they can request authentication",
    show_default=True,
    flag_value=True,
    default=_default_config.require_client_registration,
    type=bool,
    is_flag=False,
)
@click.option(
    "-n",
    "--require-nonce",
    help="Require clients to include a nonce in the authorization request to prevent replay attacks",
    show_default=True,
    flag_value=True,
    default=_default_config.require_nonce,
    type=bool,
    is_flag=False,
)
@click.option(
    "-f",
    "--no-refresh-token",
    help="Do not issue an refresh token",
    show_default=True,
    flag_value=True,
    default=not _default_config.issue_refresh_token,
    type=bool,
    is_flag=False,
)
@click.option(
    "-e",
    "--token-max-age",
    help="Max age of access and ID tokens in seconds until they expire",
    default=_default_config.access_token_max_age.total_seconds(),
    type=int,
)
def run(
    port: int,
    *,
    require_registration: bool,
    require_nonce: bool,
    no_refresh_token: bool,
    token_max_age: int,
):
    """Start an OpenID Connect Provider for testing"""
    uvicorn.run(
        app(
            require_client_registration=require_registration,
            require_nonce=require_nonce,
            issue_refresh_token=not no_refresh_token,
            access_token_max_age=timedelta(seconds=token_max_age),
        ),
        interface="wsgi",
        port=port,
    )


if __name__ == "__main__":
    run()
