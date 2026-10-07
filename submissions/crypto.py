"""Phase 5 -- encryption and integrity protection for stored submissions.

This is **application-level (server-side) encryption**, not end-to-end
encryption: the server holds both keys, so it can decrypt for authorized
journalists.  It protects report text and evidence *at rest* -- a copied
database file, backup or evidence directory is unreadable and tamper-evident
without the keys, which live only in the environment.

Construction (encrypt-then-MAC, two independent 256-bit keys)
-------------------------------------------------------------
1. AES-256-GCM (``cryptography``'s ``AESGCM``) encrypts the plaintext with a
   fresh random 96-bit nonce from ``os.urandom`` for **every** encryption.
2. HMAC-SHA-256, with a separate key, authenticates the whole package -- format
   version, timestamp, nonce and ciphertext -- together with its context (what
   the data is and which record it belongs to).

Package layout (bytes)::

    "P5" | version (1) | timestamp_us (8, big-endian) | nonce (12) | ciphertext+GCM tag | HMAC-SHA-256 (32)

Opening a package always runs in this order, and stops at the first failure:

1. structure checks (magic, version, lengths);
2. HMAC-SHA-256 verification with ``hmac.compare_digest`` (constant time) --
   **before** any decryption is attempted;
3. timestamp / replay validation: the timestamp must not be in the future
   (beyond the allowed clock skew) and must equal the timestamp of the record it
   is stored in; anything else is stale or replayed data;
4. AES-256-GCM decryption, which also checks the GCM tag.

Context binding: the record identity (``binding``) and the kind of data
(``purpose``) are included in both the HMAC and the GCM associated data, so a
valid package copied into another row, another field or another evidence file
fails verification.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import re
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"P5"
VERSION = 1
KEY_BYTES = 32           # AES-256 / HMAC-SHA-256 key size
NONCE_BYTES = 12         # 96-bit GCM nonce
TAG_BYTES = 16           # GCM authentication tag
MAC_BYTES = 32           # HMAC-SHA-256 output
_HEADER = struct.Struct(">2sBQ")  # magic, version, timestamp (microseconds)
_MIN_PACKAGE = _HEADER.size + NONCE_BYTES + TAG_BYTES + MAC_BYTES

TEXT_PREFIX = "p5:"      # marks a protected value stored in a text column
_EPOCH = datetime(1970, 1, 1)
_KEY_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")


class ProtectionError(Exception):
    """Base class for every Phase 5 failure."""


class KeyConfigurationError(ProtectionError):
    """Keys are missing or invalid.  Messages never contain key material."""


class IntegrityCheckError(ProtectionError):
    """A package failed verification and must not be trusted or decrypted.

    ``reason`` is one of ``malformed``, ``hmac``, ``timestamp`` or ``decrypt``.
    """

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


class StaleDataError(IntegrityCheckError):
    """Authentic, but from the wrong time: future-dated, stale or replayed."""

    def __init__(self, message: str):
        super().__init__("timestamp", message)


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------
@dataclass(frozen=True, repr=False)
class Keys:
    encryption: bytes
    mac: bytes

    def __repr__(self) -> str:  # never print key material
        return "Keys(<redacted>)"


def parse_key(value: str | None, name: str) -> bytes:
    """Decode one base64url key and check it is exactly 256 bits."""
    text = (value or "").strip()
    if not text:
        raise KeyConfigurationError(f"{name} is not set.")
    if not _KEY_RE.fullmatch(text):
        raise KeyConfigurationError(f"{name} is not valid base64url text.")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise KeyConfigurationError(f"{name} is not valid base64url text.") from exc
    if len(raw) != KEY_BYTES:
        raise KeyConfigurationError(
            f"{name} must decode to exactly {KEY_BYTES} bytes (256 bits); got {len(raw)}."
        )
    if len(set(raw)) < 8:
        raise KeyConfigurationError(f"{name} does not look random (placeholder value?).")
    return raw


def load_keys(encryption_key: str | None, mac_key: str | None) -> Keys:
    keys = Keys(
        encryption=parse_key(encryption_key, "PHASE5_ENCRYPTION_KEY"),
        mac=parse_key(mac_key, "PHASE5_HMAC_KEY"),
    )
    if hmac.compare_digest(keys.encryption, keys.mac):
        raise KeyConfigurationError(
            "PHASE5_ENCRYPTION_KEY and PHASE5_HMAC_KEY must be two different keys."
        )
    return keys


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------
def to_micros(moment: datetime) -> int:
    """Naive-UTC datetime -> integer microseconds since the epoch (exact)."""
    if moment.tzinfo is not None:
        raise ValueError("Timestamps must be naive UTC datetimes.")
    return (moment - _EPOCH) // timedelta(microseconds=1)


def from_micros(value: int) -> datetime:
    return _EPOCH + timedelta(microseconds=value)


# ---------------------------------------------------------------------------
# Seal / open
# ---------------------------------------------------------------------------
def _context(label: bytes, purpose: str, binding: str) -> bytes:
    """Domain-separated, length-prefixed encoding (no ambiguity between fields)."""
    parts = [purpose.encode("utf-8"), binding.encode("utf-8")]
    return label + b"".join(struct.pack(">I", len(p)) + p for p in parts)


def _mac(keys: Keys, purpose: str, binding: str, body: bytes) -> bytes:
    return hmac.new(
        keys.mac, _context(b"PPASS-P5-HMAC\x00", purpose, binding) + body, hashlib.sha256
    ).digest()


def seal(keys: Keys, plaintext: bytes, *, purpose: str, binding: str,
         timestamp: datetime) -> bytes:
    """Encrypt and authenticate ``plaintext`` into a self-contained package."""
    header = _HEADER.pack(MAGIC, VERSION, to_micros(timestamp))
    nonce = os.urandom(NONCE_BYTES)  # fresh for every encryption, never reused
    aad = _context(b"PPASS-P5-AAD\x00", purpose, binding) + header
    ciphertext = AESGCM(keys.encryption).encrypt(nonce, plaintext, aad)
    body = header + nonce + ciphertext
    return body + _mac(keys, purpose, binding, body)


def open_package(keys: Keys, package: bytes, *, purpose: str, binding: str,
                 expected_timestamp: datetime, max_skew_seconds: int = 300,
                 now: datetime | None = None) -> bytes:
    """Verify, then decrypt.  Raises ``IntegrityCheckError`` on any failure."""
    # 1. Structure.
    if not isinstance(package, (bytes, bytearray)) or len(package) < _MIN_PACKAGE:
        raise IntegrityCheckError("malformed", "Protected data is malformed or truncated.")
    magic, version, stamp = _HEADER.unpack_from(package)
    if magic != MAGIC or version != VERSION:
        raise IntegrityCheckError("malformed", "Unknown protected-data format.")

    # 2. HMAC-SHA-256 first, in constant time -- nothing is decrypted before this.
    body, received_mac = bytes(package[:-MAC_BYTES]), bytes(package[-MAC_BYTES:])
    if not hmac.compare_digest(_mac(keys, purpose, binding, body), received_mac):
        raise IntegrityCheckError("hmac", "Integrity check (HMAC-SHA-256) failed.")

    # 3. Timestamp / replay.  The package is authentic; is it the right one?
    current = to_micros(now or datetime.now(timezone.utc).replace(tzinfo=None))
    if stamp > current + max_skew_seconds * 1_000_000:
        raise StaleDataError("Protected data carries a timestamp in the future.")
    if stamp != to_micros(expected_timestamp):
        raise StaleDataError(
            "Protected data does not belong to this record's time (stale or replayed)."
        )

    # 4. Decrypt (the GCM tag is checked here too).
    header = body[:_HEADER.size]
    nonce = body[_HEADER.size:_HEADER.size + NONCE_BYTES]
    ciphertext = body[_HEADER.size + NONCE_BYTES:]
    aad = _context(b"PPASS-P5-AAD\x00", purpose, binding) + header
    try:
        return AESGCM(keys.encryption).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise IntegrityCheckError("decrypt", "Decryption failed (wrong key or damaged data).") from exc


def package_timestamp(package: bytes) -> datetime:
    """The (unverified) timestamp of a package -- for diagnostics only."""
    return from_micros(_HEADER.unpack_from(package)[2])


# ---------------------------------------------------------------------------
# Text columns
# ---------------------------------------------------------------------------
def seal_text(keys: Keys, text: str, **kwargs) -> str:
    package = seal(keys, text.encode("utf-8"), **kwargs)
    return TEXT_PREFIX + base64.urlsafe_b64encode(package).decode("ascii")


def is_sealed_text(value: str | None) -> bool:
    return bool(value) and value.startswith(TEXT_PREFIX)


def open_text(keys: Keys, value: str | None, **kwargs) -> str:
    """Never falls back to treating an unprotected value as plaintext."""
    if not is_sealed_text(value):
        raise IntegrityCheckError("malformed", "Value is not protected data.")
    try:
        package = base64.b64decode(value[len(TEXT_PREFIX):], altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise IntegrityCheckError("malformed", "Protected data is not valid base64.") from exc
    plaintext = open_package(keys, package, **kwargs)
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:  # pragma: no cover - only possible with valid keys
        raise IntegrityCheckError("malformed", "Protected text is not UTF-8.") from exc
