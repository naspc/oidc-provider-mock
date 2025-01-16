import click
import uvicorn

from . import app


@click.command()
@click.option(
    "-r",
    "--require-registration",
    is_flag=True,
    help="Require client to register before they can request authentication",
)
@click.option(
    "-p",
    "--port",
    help="Port to start server on",
    default=9400,
)
def run(require_registration: bool, port: int):
    """Start an OpenID Connect Provider for testing"""
    uvicorn.run(
        app(require_client_registration=require_registration),
        interface="wsgi",
        port=port,
    )


if __name__ == "__main__":
    run()
