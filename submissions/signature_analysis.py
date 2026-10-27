"""Digital-signature experiment (RSA-PSS with SHA-256) on a SYNTHETIC message.

The project does NOT sign submissions; this is a controlled experiment that
shows what a signature is and how it differs from a hash, an HMAC and
encryption.  A dedicated key pair (and a second, unrelated one for the
wrong-key test) is generated inside ``rsa_pss_experiment`` for each run, used,
and discarded: no private key is stored, returned, logged or rendered.

Scheme: RSASSA-PSS, SHA-256 message hash, MGF1-SHA-256, 32-byte salt
(``PSS.DIGEST_LENGTH``), public exponent 65537, 3072-bit modulus (about 128-bit
security).  PSS is randomized: signing the same message twice gives two
different signatures, and both verify.
"""

from __future__ import annotations

import random
import statistics
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

KEY_BITS = 3072
DEFAULT_SEED = 20261027


def _pss() -> padding.PSS:
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)


def _verifies(public_key, signature: bytes, message: bytes) -> bool:
    try:
        public_key.verify(signature, message, _pss(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def _flip_bit(data: bytes, bit: int) -> bytes:
    out = bytearray(data)
    out[bit // 8] ^= 0x80 >> (bit % 8)
    return bytes(out)


def _median_ms(fn, runs: int) -> float:
    samples = []
    for _ in range(runs):
        started = time.perf_counter_ns()
        fn()
        samples.append((time.perf_counter_ns() - started) / 1e6)
    return statistics.median(samples)


def rsa_pss_experiment(key_bits: int = KEY_BITS, runs: int = 20, seed: int = DEFAULT_SEED) -> dict:
    """Sign and verify a synthetic message; check that tampering is detected."""
    rng = random.Random(seed)
    message = (f"Synthetic report {rng.randrange(10_000)}: payment of {rng.randrange(100, 99_999)} "
               f"approved on day {rng.randrange(1, 29)}.").encode("ascii")

    started = time.perf_counter()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    keygen_ms = (time.perf_counter() - started) * 1000
    public_key = private_key.public_key()
    unrelated_public_key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits).public_key()

    signature = private_key.sign(message, _pss(), hashes.SHA256())
    second_signature = private_key.sign(message, _pss(), hashes.SHA256())
    sign_ms = _median_ms(lambda: private_key.sign(message, _pss(), hashes.SHA256()), runs)
    verify_ms = _median_ms(lambda: _verifies(public_key, signature, message), runs)
    del private_key  # never leaves this function

    checks = {
        "valid signature verifies": _verifies(public_key, signature, message) is True,
        "modified message (1 bit) rejected": _verifies(public_key, signature, _flip_bit(message, 13)) is False,
        "altered signature (1 bit) rejected": _verifies(public_key, _flip_bit(signature, 100), message) is False,
        "wrong public key rejected": _verifies(unrelated_public_key, signature, message) is False,
        "re-signing gives a different signature (randomized PSS)": second_signature != signature,
        "the second signature also verifies": _verifies(public_key, second_signature, message) is True,
    }
    return {
        "scheme": "RSASSA-PSS", "hash": "SHA-256", "mgf": "MGF1-SHA-256", "salt_bytes": 32,
        "key_bits": key_bits, "public_exponent": 65537, "message_bytes": len(message),
        "signature_bytes": len(signature), "runs": runs, "keygen_ms": keygen_ms,
        "sign_ms": sign_ms, "verify_ms": verify_ms, "checks": checks, "all_checks_passed": all(checks.values()),
    }
