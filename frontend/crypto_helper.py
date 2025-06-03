# crypto_helper.py

import os
import base64
from pathlib import Path
from datetime import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ─── Directory Setup ──────────────────────────────────────────────────────────
# All key files (RSA and AES) and metadata (timestamps, fingerprints) live here.
KEY_DIR = Path.home() / ".scomm" / "keys"
KEY_DIR.mkdir(parents=True, exist_ok=True)


# ─── RSA PRIVATE KEY LOADING ──────────────────────────────────────────────────
def load_rsa_private_key(username: str) -> rsa.RSAPrivateKey:
    """
    Load a user’s RSA private key PEM from: <KEY_DIR>/<username>_private_key.pem.
    Raises FileNotFoundError if no such file exists.
    """
    priv_path = KEY_DIR / f"{username}_private_key.pem"
    if not priv_path.exists():
        raise FileNotFoundError(f"Private key not found: {priv_path}")
    with open(priv_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


# ─── RSA PUBLIC KEY LOADING ───────────────────────────────────────────────────
def load_rsa_public_key(username: str, pubkey_pem: str) -> rsa.RSAPublicKey:
    """
    Given a PEM‐encoded public key string (as fetched from the server),
    load and return an RSAPublicKey object. Raises ValueError on invalid PEM.
    """
    try:
        return serialization.load_pem_public_key(pubkey_pem.encode("utf-8"))
    except Exception as e:
        raise ValueError(f"Invalid public key PEM for {username}: {e}")


# ─── PUBLIC-KEY FINGERPRINTS ───────────────────────────────────────────────────
def compute_fingerprint(pubkey_pem: str) -> str:
    """
    Compute SHA-256 fingerprint of a PEM‐encoded RSA public key.
    Returns colon-separated hex bytes, e.g. "AB:CD:12:34:…".
    """
    pubkey = serialization.load_pem_public_key(pubkey_pem.encode("utf-8"))
    der_bytes = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der_bytes)
    fp = digest.finalize()
    return ":".join(f"{b:02X}" for b in fp)


def save_fingerprint(username: str, fingerprint: str):
    """
    Save a public‐key fingerprint to: <KEY_DIR>/<username>_pubkey_fingerprint.txt.
    """
    path = KEY_DIR / f"{username}_pubkey_fingerprint.txt"
    with open(path, "w") as f:
        f.write(fingerprint)


def load_fingerprint(username: str) -> str:
    """
    Load the saved fingerprint from: <KEY_DIR>/<username>_pubkey_fingerprint.txt.
    Returns None if the file does not exist or is unreadable.
    """
    path = KEY_DIR / f"{username}_pubkey_fingerprint.txt"
    if not path.exists():
        return None
    return path.read_text().strip()


# ─── RSA ENCRYPT / DECRYPT (OAEP SHA-256) ──────────────────────────────────────
def rsa_encrypt(pubkey: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
    """
    Encrypt 'plaintext' bytes using RSA-OAEP with SHA-256.
    Returns ciphertext bytes.
    """
    return pubkey.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt(privkey: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext bytes using RSA-OAEP with SHA-256.
    Returns the original plaintext bytes.
    """
    return privkey.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ─── RSA SIGN / VERIFY (PSS SHA-256) ───────────────────────────────────────────
def rsa_sign(privkey: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """
    Sign 'data' using RSA-PSS with SHA-256. Returns signature bytes.
    """
    return privkey.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def rsa_verify(pubkey: rsa.RSAPublicKey, signature: bytes, data: bytes) -> bool:
    """
    Verify an RSA-PSS SHA-256 signature. Returns True if valid, False otherwise.
    """
    try:
        pubkey.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ─── AES‐GCM ENCRYPT / DECRYPT ─────────────────────────────────────────────────
def aes_encrypt(aes_key: bytes, plaintext: bytes) -> bytes:
    """
    AES-GCM encrypt. Given a 32-byte key and plaintext bytes,
    returns a payload: nonce(12) || ciphertext || tag(16).
    """
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 96-bit nonce
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce + ct


def aes_decrypt(aes_key: bytes, payload: bytes) -> bytes:
    """
    AES-GCM decrypt. 'payload' is nonce(12) || ciphertext+tag.
    Returns the decrypted plaintext bytes (raises on auth failure).
    """
    aesgcm = AESGCM(aes_key)
    nonce = payload[:12]
    ct_and_tag = payload[12:]
    return aesgcm.decrypt(nonce, ct_and_tag, associated_data=None)


# ─── AES KEY STORAGE ──────────────────────────────────────────────────────────
def save_aes_key(chat_id: str, version: str, aes_key: bytes):
    """
    Save a 32-byte AES key under:
      <KEY_DIR>/<chat_id>_aes_key_<version>.bin
    Example: chat_id="alice_bob", version="v1".
    """
    path = KEY_DIR / f"{chat_id}_aes_key_{version}.bin"
    with open(path, "wb") as f:
        f.write(aes_key)


def load_aes_key(chat_id: str, version: str) -> bytes:
    """
    Load the AES key from:
      <KEY_DIR>/<chat_id>_aes_key_<version>.bin
    Raises FileNotFoundError if not present.
    """
    path = KEY_DIR / f"{chat_id}_aes_key_{version}.bin"
    if not path.exists():
        raise FileNotFoundError(f"AES key file not found: {path}")
    return path.read_bytes()


# ─── RSA KEY ROTATION TIMESTAMP ────────────────────────────────────────────────
def get_last_rsa_rotation() -> datetime:
    """
    Read the last RSA rotation timestamp from:
      <KEY_DIR>/last_rsa_rotation.txt
    Returns a datetime, or None if missing/invalid.
    """
    path = KEY_DIR / "last_rsa_rotation.txt"
    if not path.exists():
        return None
    try:
        text = path.read_text().strip()
        return datetime.fromisoformat(text)
    except Exception:
        return None


def update_last_rsa_rotation():
    """
    Write the current UTC timestamp (ISO 8601) to:
      <KEY_DIR>/last_rsa_rotation.txt
    """
    path = KEY_DIR / "last_rsa_rotation.txt"
    with open(path, "w") as f:
        f.write(datetime.utcnow().isoformat())


# ─── TIMESTAMP FORMATTING ──────────────────────────────────────────────────────
def format_timestamp_ms(ms: int) -> str:
    """
    Convert a millisecond‐epoch integer to a human‐readable string:
      e.g. 1615123456789 → "2021-03-07 14:50:56"
    """
    try:
        return datetime.fromtimestamp(ms / 1000).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""
