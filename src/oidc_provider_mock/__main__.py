import logging
import os
import sys
import time
import traceback
import threading
import requests
from datetime import datetime, timedelta

import click
import uvicorn

from . import app
from ._app import Config

# Constants
JWKS_REFRESH_PADDING = 120  # 2 minutes padding before expiration
_default_config = Config


# Global cache state for JWKS
jwks_cache = {
    "keyset": None,
    "expiration": None,
    "max_age": 86400,  # Default 24 hours
    "port": 9400,
    "host": "127.0.0.1"
}

def start_jwks_refresh_task(debug: bool = False):
    """Start background task to refresh JWKS according to cache headers"""
    def refresh_loop():
        while True:
            try:
                start_time = datetime.utcnow()
                if debug:
                    print(f"\n[DEBUG] JWKS Refresh Cycle Started at {start_time.isoformat()}")
                
                jwks_uri = f"http://{jwks_cache['host']}:{jwks_cache['port']}/jwks"
                if debug:
                    print(f"[DEBUG] Fetching JWKS from: {jwks_uri}")
                
                response = requests.get(jwks_uri)
                response.raise_for_status()
                
                # Parse cache headers
                cache_control = response.headers.get('Cache-Control', '')
                max_age = jwks_cache['max_age']  # Default to existing
                
                if 'max-age' in cache_control:
                    try:
                        max_age = int(cache_control.split('max-age=')[1].split(',')[0])
                    except (ValueError, IndexError):
                        if debug:
                            print("[DEBUG] Using default max-age")
                
                expiration = start_time + timedelta(seconds=max_age)
                jwks_cache.update({
                    "keyset": response.json(),
                    "expiration": expiration,
                    "max_age": max_age,
                    "last_updated": start_time
                })
                
                if debug:
                    print(f"[DEBUG] Updated JWKS cache. Next refresh at: {expiration.isoformat()}")
                
                # Calculate sleep time with padding
                sleep_time = max(max_age - JWKS_REFRESH_PADDING, 10)  # Minimum 10s
                if debug:
                    print(f"[DEBUG] Sleeping for {sleep_time} seconds")
                time.sleep(sleep_time)
                
            except Exception as e:
                error_msg = f"JWKS refresh failed: {type(e).__name__}: {str(e)}"
                logging.error(error_msg)
                if debug:
                    traceback.print_exc()
                    print(f"[DEBUG] Retrying in 60 seconds...")
                time.sleep(60)

    if debug:
        print("[DEBUG] Starting JWKS refresh background task")
    thread = threading.Thread(target=refresh_loop, daemon=True, name="JWKS-Refresh")
    thread.start()

@click.command(context_settings={"max_content_width": 100})
@click.option(
    "--debug",
    help="Enable debug mode with verbose logging",
    is_flag=True,
    default=False
)
@click.option(
    "-p",
    "--port",
    help="Port the server listens on",
    default=9400,
    show_default=True,
)
@click.option(
    "-H",
    "--host",
    help="IP address to bind the server to",
    default="127.0.0.1",
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
    help="Do not issue a refresh token",
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
    debug: bool,
    port: int,
    host: str,
    *,
    require_registration: bool,
    require_nonce: bool,
    no_refresh_token: bool,
    token_max_age: int,
):
    """Start an OpenID Connect Provider for testing"""

    # Configure logging
    log_level = logging.DEBUG if debug else logging.INFO
    logging.getLogger().setLevel(log_level)
    
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        Logfmter(
            color=not os.getenv("NO_COLOR")
            and (handler.stream.isatty() or bool(os.getenv("FORCE_COLOR")))
        )
    )
    logging.getLogger().addHandler(handler)

    # Update cache configuration
    jwks_cache.update({
        "port": port,
        "host": host
    })
    
    # Start refresh task
    start_jwks_refresh_task(debug=debug)

    if debug:
        print(f"[DEBUG] Starting server on {host}:{port}")
        print("[DEBUG] JWKS refresh task running in background")

    uvicorn.run(
        app(
            require_client_registration=require_registration,
            require_nonce=require_nonce,
            issue_refresh_token=not no_refresh_token,
            access_token_max_age=timedelta(seconds=token_max_age),
        ),
        interface="wsgi",
        port=port,
        host=host,
        log_config=None,
    )

class Logfmter(logging.Formatter):
    def __init__(self, color: bool):
        self._color = color

    def format(self, record: logging.LogRecord) -> str:
        out = ""

        log_time = time.localtime(record.created)
        out += f"{time.strftime('%H:%M:%S', log_time)}.{record.msecs:03.0f}"

        out += " "
        if self._color:
            if record.levelno >= logging.ERROR:
                out += _ANSI_RED
            elif record.levelno >= logging.WARNING:
                out += _ANSI_YELLOW
                level_name = "WARN"
            elif record.levelno >= logging.INFO:
                out += _ANSI_BLUE
            else:
                out += _ANSI_WHITE

        level_name = record.levelname
        if level_name == "WARNING":
            level_name = "WARN"
        out += f"{level_name:6s}"

        if self._color:
            out += _ANSI_RESET

        out += f" {record.name}"

        if isinstance(record.msg, dict):
            data: dict[str, object] = dict(record.msg)  # pyright: ignore
        else:
            data = {}

        data.update({
            key: value
            for key, value in record.__dict__.items()
            if key not in _LOG_RECORD_ATTRIBUTES
        })

        color_message = data.pop("color_message", None)
        unformatted_message = data.pop("_msg", None)
        if self._color and isinstance(color_message, str):
            if record.args:
                out += " " + color_message % record.args
            else:
                out += " " + color_message
        elif unformatted_message:
            out += " " + str(unformatted_message)
        else:
            out += " " + record.getMessage()

        for key, value in data.items():
            out += f" {self._format_key(key)}={self._format_value(value)}"

        if record.exc_info:
            formatted_exception = "\n".join(
                traceback.format_exception(record.exc_info[1])
            )

            out += f" {self._format_key('exc_info')}={self._format_value(formatted_exception)}"

        return out

    @classmethod
    def _format_value(cls, value: object) -> str:
        if value is None:
            return ""
        elif isinstance(value, bool):
            return "true" if value else "false"

        value = str(value)

        if '"' in value:
            value = value.replace('"', '\\"')

        if "\n" in value:
            value = value.replace("\n", "\\n")

        if " " in value or "=" in value:
            value = f'"{value}"'

        return value

    def _format_key(self, key: str) -> str:
        if self._color:
            return f"{_ANSI_BOLD}{key}{_ANSI_RESET}"
        else:
            return key

if __name__ == "__main__":
    run()