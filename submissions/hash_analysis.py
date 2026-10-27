"""SHA-256 hashing analysis for the admin Security Analysis pages.

SYNTHETIC DATA ONLY.  Every message here is generated from a fixed seed; this
module never touches the database, stored hashes, tokens, HMACs, GCM tags or
keys.  Results describe SHA-256 on these samples; they do not prove SHA-256 is
secure (its security rests on decades of public cryptanalysis, not on tests
like these).

Methodology (all against an ideal random function as the reference):

* Strict Avalanche Criterion (SAC) -- flip one input bit; each of the n output
  bits should flip with probability 1/2, independently.  Reported: the mean flip
  rate with its z-score, the largest per-output-bit deviation against the
  largest deviation expected from sampling alone, and a chi-square test of the
  n per-bit flip counts (n degrees of freedom).
* Digest correlation -- the phi coefficient (Pearson correlation of 0/1 bits)
  between the digests of two related messages.  Ideal 0; standard error
  1/sqrt(number of bit pairs).
* Hamming distance -- between the digests of related messages it should follow
  Binomial(n, 1/2): mean n/2, standard deviation sqrt(n)/2 (128 and 8 for SHA-256).
* Preimage / second-preimage -- generic brute force only, on SHA-256 TRUNCATED to
  t bits (a bounded toy) and on a deliberately tiny candidate space.  The
  expected cost for an ideal t-bit hash is 2**t attempts.
"""

from __future__ import annotations

import hashlib
import math
import random
import statistics
import time
from typing import Callable

HashFn = Callable[[bytes], bytes]
DEFAULT_SEED = 20261027          # fixed: results are reproducible (timings aside)
# Brute-force attempts follow a geometric distribution (standard deviation about
# equal to the mean), so each truncation size is repeated several times.
DEFAULT_TRIALS = {8: 64, 12: 32, 16: 16}
SECONDS_PER_YEAR = 31_557_600
TOKEN_BITS = 192                 # the app's submission tokens: secrets.token_urlsafe(24)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------------------
# Small statistical helpers (no SciPy in this project)
# ---------------------------------------------------------------------------
def _z(observed: float, expected: float, standard_error: float) -> float | None:
    return (observed - expected) / standard_error if standard_error else None


def _normal_upper_tail(z: float) -> float:
    return 0.5 * math.erfc(z / math.sqrt(2))


def chi_square_p_value(chi2: float, df: int) -> float:
    """Upper-tail p-value via the Wilson-Hilferty normal approximation
    (accurate to a few parts in a thousand for df >= 30)."""
    k = 2 / (9 * df)
    z = ((chi2 / df) ** (1 / 3) - (1 - k)) / math.sqrt(k)
    return _normal_upper_tail(z)


def _flip_bit(data: bytes, bit: int) -> bytes:
    out = bytearray(data)
    out[bit // 8] ^= 0x80 >> (bit % 8)
    return bytes(out)


def _phi(pairs: list[tuple[int, int]], bits: int) -> float | None:
    """Phi coefficient between the bits of a and b, pooled over all pairs."""
    n = len(pairs) * bits
    ones_a = sum(a.bit_count() for a, _ in pairs)
    ones_b = sum(b.bit_count() for _, b in pairs)
    both = sum((a & b).bit_count() for a, b in pairs)
    denominator = math.sqrt(ones_a * (n - ones_a) * ones_b * (n - ones_b))
    return (n * both - ones_a * ones_b) / denominator if denominator else None


def _distance_summary(distances: list[int], bits: int) -> dict:
    n = len(distances)
    mean = statistics.fmean(distances)
    return {
        "pairs": n, "mean": mean, "sd": statistics.pstdev(distances),
        "min": min(distances), "max": max(distances),
        "expected_mean": bits / 2, "expected_sd": math.sqrt(bits) / 2,
        "z_mean": _z(mean, bits / 2, (math.sqrt(bits) / 2) / math.sqrt(n)),
    }


# ---------------------------------------------------------------------------
# 1. Correlation: strict avalanche criterion + digest correlation
#
# Assumptions.  Under the ideal ("random oracle") model, the digest of every
# distinct input is an independent uniform 256-bit string.  Then, for each
# flipped input, every output bit flips with probability 1/2, independently of
# the other output bits and of the other flips.  The four statistics below test
# different consequences of that model:
#   1. balance      mean flip rate = 1/2                      (z-test)
#   2. per bit      each output bit flips half the time      (chi-square, n df)
#   3. independence output bits do not flip together         (variance of the
#                   Hamming distance = n/4; chi-square variance test)
#   4. relation     related digests are uncorrelated         (phi, z-test)
# Each test uses alpha = 0.001.  "No evidence of deviation" means none of them
# rejected; it is NOT a proof of security.  Four tests per input means about a
# 0.4 % chance of a false alarm per input (and more when many inputs are tested).
# These tests only see first-order statistical effects; real attacks on hash
# functions (e.g. differential cryptanalysis) need far more than this.
# ---------------------------------------------------------------------------
ALPHA = 0.001
MIN_RELIABLE_FLIPS = 64          # per-bit estimates need at least ~64 flips
INPUT_CAP = 1024 * 1024          # per-report inputs: first 1 MiB of stored ciphertext


def _two_sided(z: float | None) -> float | None:
    return None if z is None else 2 * _normal_upper_tail(abs(z))


def _sac_from_pairs(pairs: list[tuple[int, int]], out_bits: int) -> dict:
    """Statistics for (digest, digest-after-one-input-bit-flip) pairs."""
    trials = len(pairs)
    flips = [0] * out_bits
    distances = []
    for base, other in pairs:
        diff = base ^ other
        distances.append(diff.bit_count())
        while diff:                                   # which output bits flipped
            low = diff & -diff
            flips[out_bits - low.bit_length()] += 1   # index 0 = most significant bit
            diff ^= low
    rates = [c / trials for c in flips]
    mean_rate = sum(flips) / (trials * out_bits)
    z_mean = _z(mean_rate, 0.5, math.sqrt(0.25 / (trials * out_bits)))
    per_bit_se = math.sqrt(0.25 / trials)
    chi2 = sum(4 * (c - trials / 2) ** 2 / trials for c in flips)
    chi2_p = chi_square_p_value(chi2, out_bits)
    max_dev = max(abs(r - 0.5) for r in rates)
    # Largest of `out_bits` roughly normal deviations: about se * sqrt(2 ln(2 * out_bits)).
    expected_max_dev = per_bit_se * math.sqrt(2 * math.log(2 * out_bits))
    # Independence: Hamming distance ~ Binomial(n, 1/2), variance n/4.  Test the
    # sample variance with (T-1) s^2 / (n/4) ~ chi-square(T-1), two-sided.
    distance = _distance_summary(distances, out_bits)
    variance = statistics.variance(distances) if trials > 1 else None
    if variance is not None:
        variance_stat = (trials - 1) * variance / (out_bits / 4)
        upper = chi_square_p_value(variance_stat, trials - 1)
        variance_p = min(1.0, 2 * min(upper, 1 - upper))
    else:
        variance_stat = variance_p = None
    phi = _phi(pairs, out_bits)
    phi_se = 1 / math.sqrt(trials * out_bits)
    phi_z = _z(phi, 0, phi_se) if phi is not None else None
    p_values = {"balance": _two_sided(z_mean), "per_bit": chi2_p,
                "independence": variance_p, "relation": _two_sided(phi_z)}
    reliable = trials >= MIN_RELIABLE_FLIPS
    rejected = [name for name, p in p_values.items() if p is not None and p < ALPHA]
    if not reliable:
        outcome = "too few flips to judge"
    elif rejected:
        outcome = "deviation flagged"
    else:
        outcome = "no evidence of deviation"
    return {
        "trials": trials, "output_bits": out_bits,
        "mean_flip_rate": mean_rate, "z_mean": z_mean,
        "min_rate": min(rates), "max_rate": max(rates),
        "max_deviation": max_dev, "expected_max_deviation": expected_max_dev, "per_bit_se": per_bit_se,
        "chi_square": chi2, "chi_square_df": out_bits, "chi_square_p": chi2_p,
        "distance": distance, "hd_variance": variance, "expected_hd_variance": out_bits / 4,
        "variance_statistic": variance_stat, "variance_df": trials - 1, "variance_p": variance_p,
        "phi": phi, "phi_se": phi_se, "phi_z": phi_z,
        "p_values": p_values, "alpha": ALPHA, "rejected": rejected,
        "reliable": reliable, "outcome": outcome,
        "consistent": reliable and not rejected,
    }


def strict_avalanche(hash_fn: HashFn = sha256, messages: int = 64, message_bytes: int = 64,
                     input_bits: int = 128, seed: int = DEFAULT_SEED) -> dict:
    """Flip each of `input_bits` evenly spaced input bits of `messages` random
    synthetic messages and record which output bits flip."""
    rng = random.Random(seed)
    total_input_bits = message_bytes * 8
    positions = [k * total_input_bits // input_bits for k in range(input_bits)]
    out_bits = len(hash_fn(b"probe")) * 8
    pairs = []
    for _ in range(messages):
        message = rng.randbytes(message_bytes)
        base = int.from_bytes(hash_fn(message), "big")
        for position in positions:
            pairs.append((base, int.from_bytes(hash_fn(_flip_bit(message, position)), "big")))
    result = _sac_from_pairs(pairs, out_bits)
    result.update(messages=messages, message_bytes=message_bytes, input_bits=input_bits, seed=seed)
    return result


def input_avalanche(data: bytes, flips: int = 256, hash_fn: HashFn = sha256, cap: int = INPUT_CAP) -> dict:
    """Strict-avalanche statistics with ONE given byte string as the base input
    (the per-report page passes a stored AES-GCM ciphertext body, never
    plaintext).  Up to `flips` evenly spaced bits of the first `cap` bytes are
    flipped one at a time.  Only statistics are returned -- no digest of the
    input -- so nothing here can serve as a fingerprint of stored data."""
    if not data:
        raise ValueError("no input bytes")
    sample = bytes(data[:cap])
    total_bits = len(sample) * 8
    count = min(flips, total_bits)
    positions = sorted({k * total_bits // count for k in range(count)})
    out_bits = len(hash_fn(b"probe")) * 8
    base = int.from_bytes(hash_fn(sample), "big")
    pairs = [(base, int.from_bytes(hash_fn(_flip_bit(sample, position)), "big")) for position in positions]
    result = _sac_from_pairs(pairs, out_bits)
    result.update(bytes_total=len(data), bytes_analysed=len(sample), capped=len(sample) < len(data))
    return result


# ---------------------------------------------------------------------------
# 2. Digest bit difference for modified synthetic messages
# ---------------------------------------------------------------------------
def _synthetic_sentence(rng: random.Random) -> str:
    return (f"Report {rng.randrange(10_000)}: payment of {rng.randrange(100, 99_999)} "
            f"to account {rng.randrange(10**7, 10**8)} on day {rng.randrange(1, 29)} "
            f"approved by clerk {rng.choice(['A', 'B', 'C', 'D'])}.")


def _synthetic_text_of(rng: random.Random, length: int) -> bytes:
    """Synthetic sentences joined and cut to exactly `length` bytes."""
    parts, size = [], 0
    while size < length:
        sentence = _synthetic_sentence(rng)
        parts.append(sentence)
        size += len(sentence) + 1
    return " ".join(parts).encode("ascii")[:length]


def _modifications(rng: random.Random) -> dict[str, Callable[[bytes], bytes]]:
    def change_char(m: bytes) -> bytes:
        i = rng.randrange(len(m))
        return m[:i] + bytes([m[i] ^ 0x01]) + m[i + 1:]

    def swap_words(m: bytes) -> bytes:
        words = m.split(b" ")
        if len(words) < 2:
            return m                     # nothing to swap; the pair is skipped
        i = rng.randrange(len(words) - 1)
        words[i], words[i + 1] = words[i + 1], words[i]
        return b" ".join(words)

    return {
        "one bit flipped": lambda m: _flip_bit(m, rng.randrange(len(m) * 8)),
        "one character changed": change_char,
        "one byte appended": lambda m: m + b".",
        "two adjacent words swapped": swap_words,
    }


def _modification_rows(rng: random.Random, make_message: Callable[[], bytes], samples: int,
                       hash_fn: HashFn) -> list[dict]:
    out_bits = len(hash_fn(b"probe")) * 8
    rows = []
    for name, modify in _modifications(rng).items():
        distances, pairs = [], []
        for _ in range(samples):
            message = make_message()
            changed = modify(message)
            if changed == message:
                continue
            a, b = (int.from_bytes(hash_fn(x), "big") for x in (message, changed))
            distances.append((a ^ b).bit_count())
            pairs.append((a, b))
        if not pairs:
            rows.append({"modification": name, "pairs": 0})
            continue
        phi = _phi(pairs, out_bits)
        phi_se = 1 / math.sqrt(len(pairs) * out_bits)
        rows.append({"modification": name, **_distance_summary(distances, out_bits),
                     "phi": phi, "phi_z": _z(phi, 0, phi_se) if phi is not None else None})
    return rows


def modification_analysis(hash_fn: HashFn = sha256, samples: int = 1000, seed: int = DEFAULT_SEED) -> list[dict]:
    """For each kind of small change to a synthetic sentence: the Hamming
    distance between the two digests and the correlation of their bits."""
    rng = random.Random(seed + 1)
    return _modification_rows(rng, lambda: _synthetic_sentence(rng).encode("ascii"), samples, hash_fn)


SIZED_CAP = 16 * 1024


def sized_modification_analysis(length: int, samples: int = 100, hash_fn: HashFn = sha256,
                                seed: int = DEFAULT_SEED) -> dict:
    """The same analysis on SYNTHETIC text of a given length (the per-report
    page passes each stored item's size, capped at 16 KiB).  The messages are
    generated text, never the report's content."""
    size = max(1, min(length, SIZED_CAP))
    rng = random.Random(seed + 5 + size)
    rows = _modification_rows(rng, lambda: _synthetic_text_of(rng, size), samples, hash_fn)
    return {"message_bytes": size, "capped": size < length, "samples": samples, "rows": rows}


# ---------------------------------------------------------------------------
# 3. Preimage and second-preimage resistance: bounded toy examples
# ---------------------------------------------------------------------------
def _truncate(digest: bytes, bits: int) -> int:
    """The first `bits` bits of a digest (bits <= 32)."""
    return int.from_bytes(digest[:4], "big") >> (32 - bits)


def _years_for(attempts_log2: float, hashes_per_second: float) -> float:
    """log10 of the years needed for 2**attempts_log2 hash computations."""
    return attempts_log2 * math.log10(2) - math.log10(hashes_per_second) - math.log10(SECONDS_PER_YEAR)


def _search(target: int, bits: int, prefix: bytes, hash_fn: HashFn, cap: int, exclude: bytes | None = None):
    for attempt in range(1, cap + 1):
        candidate = prefix + attempt.to_bytes(8, "big")
        if candidate != exclude and _truncate(hash_fn(candidate), bits) == target:
            return attempt, candidate
    return None, None


def _attempt_row(bits: int, attempts_list: list, example: dict | None) -> dict:
    """Mean attempts against the ideal 2**bits.  The standard error of the
    mean is about 2**bits / sqrt(trials) (geometric distribution)."""
    found = [a for a in attempts_list if a is not None]
    expected = 2 ** bits
    mean = statistics.fmean(found) if found else None
    se = expected / math.sqrt(len(found)) if found else None
    return {"bits": bits, "trials": len(attempts_list), "found": len(found), "mean_attempts": mean,
            "expected_attempts": expected, "standard_error": se,
            "ratio": mean / expected if mean else None,
            "z": _z(mean, expected, se) if mean and se else None,
            "within_expected": mean is not None and abs(mean - expected) <= 3 * se,
            "example": example}


def preimage_toy(bits_list=(8, 12, 16), trials=None, hash_fn: HashFn = sha256,
                 seed: int = DEFAULT_SEED) -> dict:
    """Given only a TRUNCATED digest of a secret synthetic message, brute-force
    any message with that truncated digest (a preimage of the toy hash)."""
    trials = trials or DEFAULT_TRIALS
    rng = random.Random(seed + 2)
    rows, hashed, started = [], 0, time.perf_counter()
    for bits in bits_list:
        attempts_list, example = [], None
        for trial in range(trials[bits]):
            secret = rng.randbytes(16)
            target = _truncate(hash_fn(secret), bits)
            attempts, found = _search(target, bits, b"preimage-%d-%d-" % (bits, trial), hash_fn, 20 * 2 ** bits)
            hashed += attempts or 20 * 2 ** bits
            attempts_list.append(attempts)
            if example is None and found is not None:
                example = {"target": f"{target:0{(bits + 3) // 4}x}", "found": found.hex(),
                           "found_digest": hash_fn(found).hex(), "secret_digest": hash_fn(secret).hex(),
                           "same_message": found == secret}
        found_attempts = [a for a in attempts_list if a is not None]
        rows.append(_attempt_row(bits, attempts_list, example))
    elapsed = time.perf_counter() - started
    rate = hashed / elapsed if elapsed else None
    return {"rows": rows, "hashes": hashed, "seconds": elapsed, "hashes_per_second": rate,
            "full_log10_years": _years_for(256, rate) if rate else None,
            "full_log10_years_trillion_x": _years_for(256, rate * 1e12) if rate else None}


def second_preimage_toy(bits_list=(8, 12, 16), trials=None, hash_fn: HashFn = sha256,
                        seed: int = DEFAULT_SEED) -> dict:
    """Given a synthetic message m1, brute-force a DIFFERENT message m2 whose
    truncated digest equals that of m1."""
    trials = trials or DEFAULT_TRIALS
    rng = random.Random(seed + 3)
    rows, hashed, started = [], 0, time.perf_counter()
    for bits in bits_list:
        attempts_list, example = [], None
        for trial in range(trials[bits]):
            m1 = _synthetic_sentence(rng).encode("ascii")
            target = _truncate(hash_fn(m1), bits)
            attempts, m2 = _search(target, bits, m1 + b" #", hash_fn, 20 * 2 ** bits, exclude=m1)
            hashed += attempts or 20 * 2 ** bits
            attempts_list.append(attempts)
            if example is None and m2 is not None:
                example = {"m1": m1.decode(), "m2": m2[:len(m1) + 2].decode() + "<8-byte counter " + m2[-8:].hex() + ">",
                           "truncated": f"{target:0{(bits + 3) // 4}x}",
                           "full_m1": hash_fn(m1).hex(), "full_m2": hash_fn(m2).hex()}
        found_attempts = [a for a in attempts_list if a is not None]
        rows.append(_attempt_row(bits, attempts_list, example))
    elapsed = time.perf_counter() - started
    rate = hashed / elapsed if elapsed else None
    return {"rows": rows, "hashes": hashed, "seconds": elapsed, "hashes_per_second": rate,
            "full_log10_years": _years_for(256, rate) if rate else None,
            "full_log10_years_trillion_x": _years_for(256, rate * 1e12) if rate else None}


def restricted_space_demo(hash_fn: HashFn = sha256, seed: int = DEFAULT_SEED) -> dict:
    """A full SHA-256 digest of a synthetic 4-digit PIN: the candidate space is
    only 10,000, so brute force finds it at once.  Contrast with the app's
    192-bit random submission tokens."""
    rng = random.Random(seed + 4)
    secret_pin = f"{rng.randrange(10_000):04d}"
    target = hash_fn(f"PIN-{secret_pin}".encode())
    started = time.perf_counter()
    found, attempts = None, 0
    for candidate in range(10_000):
        attempts += 1
        if hash_fn(f"PIN-{candidate:04d}".encode()) == target:
            found = f"{candidate:04d}"
            break
    elapsed = time.perf_counter() - started
    rate = attempts / elapsed if elapsed else None
    return {"candidates": 10_000, "attempts": attempts, "found": found, "correct": found == secret_pin,
            "milliseconds": elapsed * 1000, "target_digest": target.hex(),
            "token_bits": TOKEN_BITS, "token_log10_candidates": TOKEN_BITS * math.log10(2),
            "token_log10_years": _years_for(TOKEN_BITS - 1, rate) if rate else None}
