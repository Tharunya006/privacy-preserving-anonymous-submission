"""Isolated worker for bounded truncated-SHA-256 experiments.

Run only as a separate process:  python -I -S hash_worker.py
(job JSON on stdin, result JSON on stdout).  Standard library only: it never
imports the application, never reads .env and never sees a key.  The input is
a stored ENCRYPTED representation (envelope or ciphertext payload) chosen by
the server, never plaintext.

Experiments (t = number of leading digest bits that must match, 1..20):

* preimage        -- find any message m with SHA-256(m)[:t] == SHA-256(target)[:t].
                     Candidates: b"ppass-preimage-candidate:" + 8-byte counter.
* second_preimage -- find m != target with the same first t bits.
                     Candidates: target + b"|ppass-second-preimage:" + 8-byte counter
                     (always longer than, hence different from, the target).

Each counter value is one attempt.  The search stops at a match, at the attempt
budget or at the time limit -- whichever comes first -- and reports which.  A
match is re-verified from scratch before it is reported.  Truncated digests
are a toy: matching t bits costs ~2**t attempts; full SHA-256 would cost ~2**256.
"""

import base64
import hashlib
import json
import resource
import sys
import time

MAX_BITS = 20
BUDGET_FACTOR = 16                 # budget = 16 * 2**t attempts at most
CHECK_EVERY = 4096                 # attempts between time-limit checks
PREIMAGE_PREFIX = b"ppass-preimage-candidate:"
SECOND_PREIMAGE_SEPARATOR = b"|ppass-second-preimage:"


def truncate(digest: bytes, bits: int) -> int:
    return int.from_bytes(digest[:4], "big") >> (32 - bits)


def candidate_for(kind: str, target: bytes, suffix: bytes) -> bytes:
    if kind == "preimage":
        return PREIMAGE_PREFIX + suffix
    return target + SECOND_PREIMAGE_SEPARATOR + suffix


def run(job: dict) -> dict:
    kind, bits = job["kind"], int(job["bits"])
    if kind not in ("preimage", "second_preimage") or not 1 <= bits <= MAX_BITS:
        raise ValueError("invalid experiment")
    target = base64.b64decode(job["data_b64"], validate=True)
    target_bits = truncate(hashlib.sha256(target).digest(), bits)
    budget = min(int(job["budget"]), BUDGET_FACTOR * 2 ** bits)
    time_limit = float(job["time_limit"])

    base_state = hashlib.sha256(target + SECOND_PREIMAGE_SEPARATOR) if kind == "second_preimage" else None
    started = time.perf_counter()
    deadline = time.monotonic() + time_limit
    attempts, found, stop_reason = 0, None, "budget exhausted"
    for counter in range(1, budget + 1):
        suffix = counter.to_bytes(8, "big")
        if kind == "preimage":
            digest = hashlib.sha256(PREIMAGE_PREFIX + suffix).digest()
        else:
            state = base_state.copy()
            state.update(suffix)
            digest = state.digest()
        attempts = counter
        if truncate(digest, bits) == target_bits:
            found, stop_reason = suffix, "match found"
            break
        if counter % CHECK_EVERY == 0 and time.monotonic() > deadline:
            stop_reason = "time limit reached"
            break
    elapsed = time.perf_counter() - started

    result = {"kind": kind, "bits": bits, "budget": budget, "time_limit": time_limit,
              "attempts": attempts, "elapsed_seconds": elapsed, "outcome": stop_reason,
              "target_prefix": f"{target_bits:0{(bits + 3) // 4}x}", "expected_attempts": 2 ** bits,
              "found": found is not None}
    if found is not None:
        candidate = candidate_for(kind, target, found)
        full = hashlib.sha256(candidate).digest()           # recomputed from scratch
        result.update({
            "counter_hex": found.hex(), "candidate_bytes": len(candidate),
            "candidate_sha256": full.hex(),
            "worker_verified": truncate(full, bits) == target_bits and (kind == "preimage" or candidate != target),
            "differs_from_target": candidate != target,
        })
    return result


def main() -> int:
    cpu = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    _soft, hard = resource.getrlimit(resource.RLIMIT_CPU)     # hard stop for runaway CPU use
    new_hard = cpu + 5 if hard == resource.RLIM_INFINITY else min(hard, cpu + 5)
    resource.setrlimit(resource.RLIMIT_CPU, (min(cpu, new_hard), new_hard))
    job = json.loads(sys.stdin.buffer.read())
    sys.stdout.write(json.dumps(run(job)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
