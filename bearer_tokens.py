import json
import logging
import os
from typing import Callable, Dict, Optional

import requests
import yaml
from apscheduler.schedulers.background import BackgroundScheduler

TOKEN_FILE = "token.json"
SECRETS_FILE = os.environ.get("REST_INCANTATION_SECRETS", "config/secrets.yaml")


def save_token(token_info: Dict[str, str], token_file: str = TOKEN_FILE) -> None:
    with open(token_file, "w") as file:
        json.dump(token_info, file)


def load_token(token_file: str = TOKEN_FILE) -> Optional[Dict[str, str]]:
    try:
        with open(token_file, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return None


def load_secrets(file_path: str = SECRETS_FILE) -> Dict[str, str]:
    if not os.path.exists(file_path):
        return {}
    try:
        with open(file_path, "r") as file:
            return yaml.safe_load(file) or {}
    except (OSError, yaml.YAMLError) as exc:
        logging.error("Error loading secrets file %s: %s", file_path, exc)
        return {}


def renew_token(
    token_endpoint: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    token_file: str = TOKEN_FILE,
    secrets_file: str = SECRETS_FILE,
) -> Optional[Dict[str, str]]:
    secrets = load_secrets(secrets_file)
    token_endpoint = token_endpoint or secrets.get("token_endpoint")
    client_id = client_id or secrets.get("client_id")
    client_secret = client_secret or secrets.get("client_secret")
    if not token_endpoint or not client_id or not client_secret:
        logging.error("Missing token configuration in %s.", secrets_file)
        return None

    try:
        response = requests.post(
            token_endpoint,
            data={"grant_type": "client_credentials"},
            auth=(client_id, client_secret),
            timeout=10,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        logging.error("Token renewal failed: %s", exc)
        return None

    token_info = response.json()
    save_token(token_info, token_file=token_file)
    return token_info


def get_token(token_file: str = TOKEN_FILE) -> Optional[str]:
    token_info = load_token(token_file=token_file)
    if not token_info or "access_token" not in token_info:
        token_info = renew_token(token_file=token_file)
    if not token_info:
        return None
    return token_info["access_token"]


def start_token_renewal(
    renew_fn: Callable[[], Optional[Dict[str, str]]],
    interval_hours: int = 1,
) -> BackgroundScheduler:
    scheduler = BackgroundScheduler()
    scheduler.add_job(renew_fn, "interval", hours=interval_hours)
    scheduler.start()
    return scheduler
