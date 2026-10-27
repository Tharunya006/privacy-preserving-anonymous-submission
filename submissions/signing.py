"""Server-side digital signatures for accepted submissions (RSA-PSS + SHA-256).

What a valid signature shows: the signed stored data (the encrypted report,
its evidence and the listed metadata) has not changed since the server
accepted it, and it was signed with the server's trusted signing key.  It does
NOT show who submitted the report -- sources are anonymous -- and it says
nothing about whether the content is true.

Scheme: RSASSA-PSS, SHA-256, MGF1-SHA-256, 32-byte salt, RSA >= 3072 bits.
Key ID: the first 16 bytes (hex) of SHA-256 over the public key's DER
SubjectPublicKeyInfo -- derived from the key itself, so it cannot disagree
with it.  The private key lives in a passphrase-encrypted PKCS#8 PEM file
outside the repository and the database; it is never placed in Flask config.

Manifest v1 (the exact signed bytes) -- deterministic and unambiguous:

    b"PPASS-SUBMISSION-MANIFEST\\x00" || version (1 byte)
    then fields in this fixed order, each  len(name) u16 || name || len(value) u32 || value:
      algorithm, key_id, submission_id (u64), created_at (u64 us), signed_at (u64 us),
      title_envelope_sha256, content_envelope_sha256, evidence_count (u32),
      and per evidence file, sorted by id:
      evidence_id (u64), stored_name, extension, size_bytes (u64),
      evidence_created_at (u64 us), evidence_envelope_sha256

"envelope" = the exact stored protected package (text: the base64url-decoded
column value; evidence: the stored file).  Status and updated_at change during
the workflow and are deliberately NOT signed.  The source's token hash is not
included (it is already bound into each envelope's HMAC).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import stat
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from . import crypto

ALGORITHM = "RSASSA-PSS-SHA256"
SIGNATURE_FORMAT = 1
MANIFEST_VERSION = 1
MIN_KEY_BITS = 3072
SALT_BYTES = 32
DOMAIN = b"PPASS-SUBMISSION-MANIFEST\x00"


class SigningConfigurationError(Exception):
    """A configured key is unusable (missing file, wrong passphrase, unsafe permissions...)."""


class SigningUnavailable(Exception):
    """No signing key is configured, so new submissions cannot be accepted."""


class SigningFailed(Exception):
    """Signing a just-accepted submission failed; the whole submission is rolled back."""


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------
def key_id_for(public_key) -> str:
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).digest()[:16].hex()


@dataclass(repr=False)
class SigningKeys:
    """The current private key (or None) and all trusted public keys by key ID."""

    private_key: object | None
    key_id: str | None
    trusted: dict = field(default_factory=dict)

    def __repr__(self) -> str:  # never show key material
        return f"<SigningKeys key_id={self.key_id} can_sign={self.private_key is not None} trusted={len(self.trusted)}>"

    @property
    def can_sign(self) -> bool:
        return self.private_key is not None


def _check_rsa(key, what: str) -> None:
    if not isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        raise SigningConfigurationError(f"{what} is not an RSA key.")
    if key.key_size < MIN_KEY_BITS:
        raise SigningConfigurationError(f"{what} is {key.key_size} bits; at least {MIN_KEY_BITS} are required.")


def _private_file_is_safe(path: Path) -> bool:
    return not (path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO))


def load_signing_keys(key_file: str | None, passphrase: str | None, trusted_dir: str | None) -> SigningKeys:
    """Load the signing key (if configured) and the trusted public keys.

    No key file configured -> a key set that cannot sign (submissions are then
    refused) but can still verify existing signatures from ``trusted_dir``.
    A configured but unusable key raises SigningConfigurationError.  Error
    messages never contain key material or the passphrase."""
    private_key = key_id = None
    trusted: dict = {}
    if key_file:
        path = Path(key_file).expanduser()
        if not path.is_file():
            raise SigningConfigurationError("PHASE7_SIGNING_KEY_FILE does not point to a file.")
        if not _private_file_is_safe(path):
            raise SigningConfigurationError("The signing key file is readable by other users; run chmod 600 on it.")
        if not passphrase:
            raise SigningConfigurationError("PHASE7_SIGNING_KEY_PASSPHRASE is not set (the key file must be encrypted).")
        try:
            private_key = serialization.load_pem_private_key(path.read_bytes(), passphrase.encode("utf-8"))
        except (ValueError, TypeError) as exc:
            raise SigningConfigurationError("The signing key could not be loaded (wrong passphrase or not an encrypted PEM key).") from exc
        _check_rsa(private_key, "The signing key")
        key_id = key_id_for(private_key.public_key())
        trusted[key_id] = private_key.public_key()
    if trusted_dir:
        directory = Path(trusted_dir).expanduser()
        if not directory.is_dir():
            raise SigningConfigurationError("PHASE7_TRUSTED_PUBLIC_KEY_DIR is not a directory.")
        if directory.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise SigningConfigurationError("The trusted public key directory is writable by other users.")
        for pem in sorted(directory.glob("*.pem")):
            try:
                public_key = serialization.load_pem_public_key(pem.read_bytes())
            except ValueError as exc:
                raise SigningConfigurationError(f"{pem.name} is not a PEM public key.") from exc
            _check_rsa(public_key, pem.name)
            trusted[key_id_for(public_key)] = public_key
    return SigningKeys(private_key=private_key, key_id=key_id, trusted=trusted)


_EPHEMERAL_TEST_KEY = None


def ephemeral_test_keys() -> SigningKeys:
    """TESTING ONLY: one in-memory key per test process, never written anywhere."""
    global _EPHEMERAL_TEST_KEY
    if _EPHEMERAL_TEST_KEY is None:
        _EPHEMERAL_TEST_KEY = rsa.generate_private_key(public_exponent=65537, key_size=MIN_KEY_BITS)
    key_id = key_id_for(_EPHEMERAL_TEST_KEY.public_key())
    return SigningKeys(private_key=_EPHEMERAL_TEST_KEY, key_id=key_id,
                       trusted={key_id: _EPHEMERAL_TEST_KEY.public_key()})


def generate_key_files(out_dir: str | os.PathLike, passphrase: str, key_bits: int = MIN_KEY_BITS) -> tuple[Path, Path, str]:
    """Create a new key pair: an encrypted private PEM (0600) and a public PEM.
    Refuses to overwrite.  Returns (private_path, public_path, key_id)."""
    if key_bits < MIN_KEY_BITS:
        raise SigningConfigurationError(f"Use at least {MIN_KEY_BITS} bits.")
    if len(passphrase) < 12:
        raise SigningConfigurationError("Use a passphrase of at least 12 characters.")
    directory = Path(out_dir).expanduser()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    key_id = key_id_for(private_key.public_key())
    private_path = directory / f"signing-{key_id}.pem"
    public_path = directory / f"signing-{key_id}.pub.pem"
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase.encode("utf-8")))
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(private_pem)
    public_pem = private_key.public_key().public_bytes(serialization.Encoding.PEM,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo)
    fd = os.open(public_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "wb") as handle:
        handle.write(public_pem)
    return private_path, public_path, key_id


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------
def _field(name: str, value: bytes) -> bytes:
    encoded = name.encode("ascii")
    return len(encoded).to_bytes(2, "big") + encoded + len(value).to_bytes(4, "big") + value


def _u64(number: int) -> bytes:
    return int(number).to_bytes(8, "big")


def _time(value: datetime) -> bytes:
    return _u64(crypto.to_micros(value))


@dataclass
class EvidenceEntry:
    id: int
    stored_name: str
    extension: str
    size_bytes: int
    created_at: datetime
    envelope: bytes


def text_envelope(value: str | None) -> bytes:
    """The exact stored package of a sealed text column (raises ValueError otherwise)."""
    if not crypto.is_sealed_text(value):
        raise ValueError("not a sealed text value")
    try:
        return base64.b64decode(value[len(crypto.TEXT_PREFIX):], altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid sealed text value") from exc


def build_manifest(*, key_id: str, submission_id: int, created_at: datetime, signed_at: datetime,
                   title_envelope: bytes, content_envelope: bytes, evidence: list[EvidenceEntry]) -> bytes:
    parts = [DOMAIN, bytes([MANIFEST_VERSION]),
             _field("algorithm", ALGORITHM.encode("ascii")),
             _field("key_id", key_id.encode("ascii")),
             _field("submission_id", _u64(submission_id)),
             _field("created_at", _time(created_at)),
             _field("signed_at", _time(signed_at)),
             _field("title_envelope_sha256", hashlib.sha256(title_envelope).digest()),
             _field("content_envelope_sha256", hashlib.sha256(content_envelope).digest()),
             _field("evidence_count", len(evidence).to_bytes(4, "big"))]
    for entry in sorted(evidence, key=lambda e: e.id):
        parts += [_field("evidence_id", _u64(entry.id)),
                  _field("stored_name", entry.stored_name.encode("ascii")),
                  _field("extension", entry.extension.encode("ascii")),
                  _field("size_bytes", _u64(entry.size_bytes)),
                  _field("evidence_created_at", _time(entry.created_at)),
                  _field("evidence_envelope_sha256", hashlib.sha256(entry.envelope).digest())]
    return b"".join(parts)


# ---------------------------------------------------------------------------
# Sign / verify
# ---------------------------------------------------------------------------
def _pss() -> padding.PSS:
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=SALT_BYTES)


def sign_manifest(keys: SigningKeys, manifest: bytes) -> bytes:
    if not keys.can_sign:
        raise SigningUnavailable("No signing key is configured.")
    return keys.private_key.sign(manifest, _pss(), hashes.SHA256())


def verify_manifest(public_key, signature: bytes, manifest: bytes) -> bool:
    try:
        public_key.verify(signature, manifest, _pss(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False
