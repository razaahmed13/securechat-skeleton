"""
Common Utility Helpers.

- Base64 encoding/decoding.
- SHA-256 hashing.
- Timestamp generation.
- Certificate serialization (for JSON).
- Nonce generation.
"""

import os
import base64
import hashlib
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# Skeleton Functions

def now_ms() -> int:
    """Returns the current time in milliseconds since the Unix epoch."""
    return int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000)

def b64e(b: bytes) -> str:
    """Encodes bytes into a Base64 string (UTF-8)."""
    return base64.b64encode(b).decode('utf-8')

def b64d(s: str) -> bytes:
    """Decodes a Base64 string (UTF-8) into bytes."""
    try:
        return base64.b64decode(s)
    except (TypeError, base64.binascii.Error):
        raise ValueError("Invalid Base64 string.")

def sha256_hex(data: bytes) -> str:
    """
    Returns the 64-character hex representation of the SHA-256 hash.
    Used for storing the password hash in the database.
    """
    return hashlib.sha256(data).hexdigest()

# Additional Helper Functions (Required by Protocol)

def sha256_bytes(data: bytes) -> bytes:
    """Returns the raw 32-byte SHA-256 hash of the data."""
    return hashlib.sha256(data).digest()

def generate_nonce(length: int = 16) -> bytes:
    """Generates a secure random nonce of the specified length."""
    return os.urandom(length)

def cert_to_b64_str(cert: x509.Certificate) -> str:
    """
    Serializes an x509.Certificate object into a Base64 string
    so it can be sent in a JSON message.
    """
    # 1. Convert certificate object to PEM bytes
    pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
    # 2. Encode PEM bytes as Base64 string
    return b64e(pem_bytes)

def b64_str_to_cert(b64_str: str) -> x509.Certificate:
    """
    Deserializes a Base64 string back into an x509.Certificate object.
    """
    try:
        # 1. Decode Base64 string to PEM bytes
        pem_bytes = b64d(b64_str)
        # 2. Load PEM bytes into certificate object
        return x509.load_pem_x509_certificate(pem_bytes)
    except Exception as e:
        raise ValueError(f"Failed to decode certificate: {e}")