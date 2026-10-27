"""Bounded queue for the isolated hash-experiment worker (``hash_worker.py``).

The web request only validates and enqueues a job; the search itself runs in a
separate operating-system process:

* ``python -I -S hash_worker.py`` -- isolated mode, no site-packages, standard
  library only; it never imports the application, so it never loads ``.env``
  or any key;
* a minimal environment (no application variables);
* a CPU-time limit set inside the worker, an attempt budget and a search time
  limit, and a wall-clock timeout after which the process is killed;
* one worker at a time, at most ``MAX_PENDING`` queued or running jobs in total,
  and a per-admin cooldown between submissions.

Results are kept in memory only (lost on restart), at most ``KEEP`` jobs.  A
job record holds no input bytes after the run -- only the experiment
parameters and the outcome.  Every reported match is verified again here,
independently of the worker, before it is shown as verified.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import threading
import time
import uuid
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

WORKER = Path(__file__).resolve().with_name("hash_worker.py")
KINDS = {"preimage": "Preimage", "second_preimage": "Second preimage"}
ALLOWED_BITS = (8, 12, 16, 20)
BUDGET_FACTOR = 16
SEARCH_TIME_LIMIT = 20.0          # seconds of searching per job
CPU_LIMIT = 30                    # seconds, enforced inside the worker
WALL_TIMEOUT = 45.0               # seconds, the worker process is killed after this
MAX_PENDING = 3                   # queued + running jobs, all admins together
COOLDOWN = 10.0                   # seconds between submissions by one admin
KEEP = 50                         # finished jobs kept in memory
PREIMAGE_PREFIX = b"ppass-preimage-candidate:"
SECOND_PREIMAGE_SEPARATOR = b"|ppass-second-preimage:"


class JobRejected(Exception):
    """The request is valid but a limit (queue, cooldown) refuses it for now."""


def _truncate(digest: bytes, bits: int) -> int:
    return int.from_bytes(digest[:4], "big") >> (32 - bits)


def verify_match(kind: str, bits: int, target: bytes, counter_hex: str) -> bool:
    """Independent check of a reported match, recomputed from scratch."""
    suffix = bytes.fromhex(counter_hex)
    if len(suffix) != 8:
        return False
    candidate = (PREIMAGE_PREFIX + suffix if kind == "preimage"
                 else target + SECOND_PREIMAGE_SEPARATOR + suffix)
    if kind == "second_preimage" and candidate == target:
        return False
    return _truncate(hashlib.sha256(candidate).digest(), bits) == _truncate(hashlib.sha256(target).digest(), bits)


class HashJobManager:
    def __init__(self, *, python: str = sys.executable, max_pending: int = MAX_PENDING,
                 cooldown: float = COOLDOWN, search_time_limit: float = SEARCH_TIME_LIMIT,
                 wall_timeout: float = WALL_TIMEOUT, keep: int = KEEP):
        self.python, self.max_pending, self.cooldown = python, max_pending, cooldown
        self.search_time_limit, self.wall_timeout, self.keep = search_time_limit, wall_timeout, keep
        self._lock = threading.Lock()
        self._jobs: OrderedDict[str, dict] = OrderedDict()
        self._futures: dict = {}
        self._last_submit: dict[int, float] = {}
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="hash-experiment")

    # -- submission ---------------------------------------------------------
    def submit(self, *, admin_id: int, reference: str, item_key: str, item_label: str,
               representation: str, data: bytes, kind: str, bits: int) -> str:
        if kind not in KINDS or bits not in ALLOWED_BITS or representation not in ("envelope", "payload"):
            raise ValueError("invalid experiment parameters")
        if not data:
            raise ValueError("no bytes to analyse")
        now = time.monotonic()
        with self._lock:
            pending = sum(1 for j in self._jobs.values() if j["status"] in ("queued", "running"))
            if pending >= self.max_pending:
                raise JobRejected(f"{pending} experiments are already queued or running; try again when they finish.")
            last = self._last_submit.get(admin_id)
            if last is not None and now - last < self.cooldown:
                raise JobRejected(f"Please wait {self.cooldown - (now - last):.0f} s before starting another experiment.")
            self._last_submit[admin_id] = now
            job_id = uuid.uuid4().hex
            self._jobs[job_id] = {
                "id": job_id, "reference": reference, "item_key": item_key, "item_label": item_label,
                "representation": representation, "kind": kind, "kind_label": KINDS[kind], "bits": bits,
                "budget": BUDGET_FACTOR * 2 ** bits, "status": "queued", "submitted_at": datetime.now(timezone.utc),
                "finished_at": None, "result": None, "error": None, "server_verified": None,
            }
            self._trim()
        self._futures[job_id] = self._executor.submit(self._run, job_id, bytes(data))
        return job_id

    def _trim(self) -> None:
        finished = [jid for jid, j in self._jobs.items() if j["status"] not in ("queued", "running")]
        while len(self._jobs) > self.keep and finished:
            self._jobs.pop(finished.pop(0), None)

    # -- execution (worker thread -> separate process) ------------------------
    def _run(self, job_id: str, data: bytes) -> None:
        with self._lock:
            job = self._jobs[job_id]
            job["status"] = "running"
        payload = json.dumps({"kind": job["kind"], "bits": job["bits"], "budget": job["budget"],
                              "time_limit": self.search_time_limit,
                              "data_b64": base64.b64encode(data).decode("ascii")}).encode("ascii")
        status, result, error, verified = "failed", None, None, None
        try:
            proc = subprocess.run(
                [self.python, "-I", "-S", str(WORKER), str(CPU_LIMIT)],
                input=payload, capture_output=True, timeout=self.wall_timeout,
                env={"PATH": "/usr/bin:/bin", "LANG": "C"}, cwd=str(WORKER.parent), check=False)
            if proc.returncode != 0:
                error = f"worker exited with code {proc.returncode}"
            else:
                result = json.loads(proc.stdout)
                status = "done"
                if result.get("found"):
                    verified = verify_match(job["kind"], job["bits"], data, result["counter_hex"])
        except subprocess.TimeoutExpired:
            status, error = "timed out", f"worker killed after {self.wall_timeout:.0f} s"
        except (ValueError, KeyError) as exc:
            error = f"invalid worker output ({type(exc).__name__})"
        with self._lock:
            job.update(status=status, result=result, error=error, server_verified=verified,
                       finished_at=datetime.now(timezone.utc))
            self._futures.pop(job_id, None)

    # -- reading --------------------------------------------------------------
    def jobs_for(self, reference: str) -> list[dict]:
        with self._lock:
            return [dict(j) for j in reversed(self._jobs.values()) if j["reference"] == reference]

    def get(self, job_id: str) -> dict | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return dict(job) if job else None

    def wait(self, job_id: str, timeout: float = 60.0) -> dict | None:
        """Block until a job has finished (used by tests and the CLI)."""
        future = self._futures.get(job_id)
        if future is not None:
            future.result(timeout=timeout)
        return self.get(job_id)
