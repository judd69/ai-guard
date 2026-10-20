"""Clean, hand-reviewed-style code — the scanner should stay quiet here."""
import json
import os
import subprocess
from pathlib import Path

import requests

API_KEY = os.environ.get("API_KEY", "changeme")  # dummy default -> skipped


def run_query(user_input: str) -> str:
    # Parameterized in real code; here we just echo safely.
    return f"user={user_input}"


def load_data(blob: bytes):
    return json.loads(blob.decode("utf-8"))


def fetch(url: str) -> str:
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    return response.text


def list_dir(path: str) -> list:
    result = subprocess.run(["ls", path], capture_output=True, text=True, check=False)
    return result.stdout.splitlines()


def sloppy_but_handled() -> None:
    try:
        list_dir("/tmp")
    except OSError as exc:
        print(f"listing failed: {exc}")


if __name__ == "__main__":
    print(Path(".").resolve())
