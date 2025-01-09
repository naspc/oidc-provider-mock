from typing import Annotated

import typer
import uvicorn

run = typer.Typer(
    pretty_exceptions_enable=False,
    rich_markup_mode=None,
)


@run.command()
def main(
    reload: Annotated[
        bool,
        typer.Option(
            help="Reload the server when code or templates change",
            hidden=True,  # Only used for development
        ),
    ] = False,
):
    """Start an OpenID Connect Provider for testing"""
    uvicorn.run(
        "oidc_provider_mock:app",
        factory=True,
        interface="wsgi",
        port=9000,
        reload=reload,
        reload_includes=["*.py", "src/**/templates/*"] if reload else None,
    )


if __name__ == "__main__":
    run()
