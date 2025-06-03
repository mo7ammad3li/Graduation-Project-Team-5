# api.py

import requests

API_BASE = "http://127.0.0.1:5000/api"


class APIError(Exception):
    """Custom exception for API errors."""
    pass


def register(wallet_id: str, password: str, months: int) -> dict:
    """
    Register a new user.
    Returns JSON response containing at least {"subaddress": "..."} or raises APIError.
    """
    url = f"{API_BASE}/register"
    payload = {"wallet_id": wallet_id, "password": password, "period": months}
    resp = requests.post(url, json=payload)
    try:
        data = resp.json()
    except ValueError:
        raise APIError(f"Non-JSON response: {resp.text}")

    if resp.status_code != 200:
        err = data.get("error") or data.get("message") or resp.text
        raise APIError(f"Registration failed: {err}")
    return data


def login(wallet_id: str, password: str) -> dict:
    """
    Log in an existing user.
    Returns JSON response containing at least {"access_token": "..."} or raises APIError.
    """
    url = f"{API_BASE}/login"
    payload = {"wallet_id": wallet_id, "password": password}
    resp = requests.post(url, json=payload)
    try:
        data = resp.json()
    except ValueError:
        raise APIError(f"Non-JSON response: {resp.text}")

    if resp.status_code != 200:
        err = data.get("error") or data.get("message") or resp.text
        raise APIError(f"Login failed: {err}")
    return data


def get_subscription_status(token: str, wallet_id: str) -> dict:
    """
    Fetch current subscription end date.
    Expects GET /api/subscription/status/<wallet_id> with Bearer token.
    Returns JSON {"end_date": "YYYY-MM-DD"} or raises APIError.
    """
    url = f"{API_BASE}/subscription/status/{wallet_id}"
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers)
    try:
        data = resp.json()
    except ValueError:
        raise APIError(f"Non-JSON response: {resp.text}")

    if resp.status_code != 200:
        err = data.get("error") or data.get("message") or resp.text
        raise APIError(f"Fetch subscription status failed: {err}")
    return data


def renew_subscription(token: str, wallet_id: str, months: int) -> dict:
    """
    Request a new subaddress to renew subscription.
    Expects POST /api/subscription/renew with Bearer token.
    Returns JSON {"subaddress": "..."} or raises APIError.
    """
    url = f"{API_BASE}/subscription/renew"
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"wallet_id": wallet_id, "months": months}
    resp = requests.post(url, json=payload, headers=headers)
    try:
        data = resp.json()
    except ValueError:
        raise APIError(f"Non-JSON response: {resp.text}")

    if resp.status_code != 200:
        err = data.get("error") or data.get("message") or resp.text
        raise APIError(f"Renew subscription failed: {err}")
    return data


def check_payment_status(wallet_id: str) -> dict:
    """
    Poll payment status for registration or renewal.
    Expects GET /api/status/<wallet_id>.
    Returns JSON {"is_active": True/False} or raises APIError.
    """
    url = f"{API_BASE}/status/{wallet_id}"
    resp = requests.get(url)
    try:
        data = resp.json()
    except ValueError:
        raise APIError(f"Non-JSON response: {resp.text}")

    if resp.status_code != 200:
        err = data.get("error") or data.get("message") or resp.text
        raise APIError(f"Check payment status failed: {err}")
    return data


def get_messages(token: str) -> list:
    """
    Fetch all messages for the logged-in user.
    Expects GET /api/messages with Bearer token.
    Returns a list of message objects or raises APIError.
    """
    url = f"{API_BASE}/messages"
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers)
    try:
        data = resp.json()
    except ValueError:
        raise APIError(f"Non-JSON response: {resp.text}")

    if resp.status_code != 200:
        err = data.get("error") or data.get("message") or resp.text
        raise APIError(f"Fetch messages failed: {err}")
    return data


def send_message(token: str, to_wallet: str, message: str, timestamp: int, signature: str = "") -> dict:
    """
    Send a message to another wallet.
    Expects POST /api/message/send with Bearer token.
    Returns JSON success or raises APIError.
    """
    url = f"{API_BASE}/message/send"
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "to_wallet": to_wallet,
        "message": message,
        "signature": signature,
        "timestamp": timestamp
    }
    resp = requests.post(url, json=payload, headers=headers)
    try:
        data = resp.json()
    except ValueError:
        raise APIError(f"Non-JSON response: {resp.text}")

    if resp.status_code != 200:
        err = data.get("error") or data.get("message") or resp.text
        raise APIError(f"Send message failed: {err}")
    return data


def change_password(token: str, wallet_id: str, current_password: str, new_password: str) -> dict:
    """
    Change the user’s password.
    Expects POST /api/change_password with Bearer token.
    Returns JSON {"message": "..."} or raises APIError.
    """
    url = f"{API_BASE}/change_password"
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "wallet_id": wallet_id,
        "current_password": current_password,
        "new_password": new_password
    }
    resp = requests.post(url, json=payload, headers=headers)
    try:
        data = resp.json()
    except ValueError:
        raise APIError(f"Non-JSON response: {resp.text}")

    if resp.status_code != 200:
        err = data.get("error") or data.get("message") or resp.text
        raise APIError(f"Change password failed: {err}")
    return data


def block_user(token: str, wallet_id: str, blocked_wallet: str, note: str = "") -> dict:
    """
    Block another user.
    Expects POST /api/block_user with Bearer token.
    Returns JSON {"message": "..."} or raises APIError.
    """
    url = f"{API_BASE}/block_user"
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "wallet_id": wallet_id,
        "blocked_wallet": blocked_wallet,
        "note": note
    }
    resp = requests.post(url, json=payload, headers=headers)
    try:
        data = resp.json()
    except ValueError:
        raise APIError(f"Non-JSON response: {resp.text}")

    if resp.status_code != 200:
        err = data.get("error") or data.get("message") or resp.text
        raise APIError(f"Block user failed: {err}")
    return data
