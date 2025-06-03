# utils.py

import re
import time
from typing import Any
from PyQt5.QtWidgets import QMessageBox, QWidget


def is_valid_monero_address(address: str) -> bool:
    """
    Basic check for a Monero address (95 characters, Base58).
    Note: Mainnet addresses start with '4'; Stagenet addresses start with '9'.
    This does NOT guarantee the address is on‐chain—it only checks format.
    """
    if not address or len(address) != 95:
        return False

    # Base58 characters (no 0, O, I, l)
    base58_regex = re.compile(r"^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{95}$")
    return bool(base58_regex.match(address))


def format_timestamp_ms(ms: int) -> str:
    """
    Convert a millisecond‐epoch timestamp to a human‐readable string.
    E.g., 1615123456789 → "2021-03-07 14:50:56"
    """
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ms / 1000))
    except Exception:
        return ""


def validate_positive_int(text: str) -> bool:
    """
    Returns True if `text` represents a positive integer (e.g., "1", "12").
    """
    if not text:
        return False
    return text.isdigit() and int(text) > 0


def show_error(parent: QWidget, title: str, message: str) -> None:
    """
    Display a modal error dialog with the given title and message.
    """
    QMessageBox.critical(parent, title, message)


def show_warning(parent: QWidget, title: str, message: str) -> None:
    """
    Display a modal warning dialog with the given title and message.
    """
    QMessageBox.warning(parent, title, message)
