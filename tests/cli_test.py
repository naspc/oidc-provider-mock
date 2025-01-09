import subprocess
import time

import requests


def test_cli():
    with subprocess.Popen(
        ["oidc-provider-mock"],
        stdin=None,
        text=True,
    ) as process:
        try:
            time.sleep(0.5)
            base_url = "http://127.0.0.1:9000"
            response = requests.get(f"{base_url}/.well-known/openid-configuration")
            assert response.status_code == 200
            body = response.json()
            assert body["issuer"] == base_url
        finally:
            process.terminate()
