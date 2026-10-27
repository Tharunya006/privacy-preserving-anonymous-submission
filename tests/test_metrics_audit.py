"""Metrics audit: stored representations, isolated hash experiments, the
signature experiment and the corrected controlled-experiment labels."""

from __future__ import annotations

import ast
import base64
import hashlib
import io
import os
import re
import stat
from pathlib import Path

import pytest
from PIL import Image

from phase2 import create_app
from phase2.extensions import db
from phase2.models import AuditLog
from phase2.services import create_admin
from submissions import hash_jobs, hash_worker, services, signature_analysis
from submissions import security_analysis as sa
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, JOURNALIST_PASSWORD, login

LEGACY_TITLE, LEGACY_BODY = "LEGACY-TITLE-PLAIN", "LEGACY-BODY-PLAIN"
LEGACY_FILE = b"LEGACY-FILE-PLAIN" * 10


def png(size=(40, 30)) -> bytes:
    buffer = io.BytesIO()
    Image.effect_noise(size, 50).convert("RGB").save(buffer, format="PNG")
    return buffer.getvalue()


@pytest.fixture()
def reports(app):
    enc, token = services.create_submission("Audit title MARKER-T", "Audit body MARKER-B " * 20, ("png", png()))
    legacy, _ = services.create_submission("x", "x", ("txt", b"placeholder"))
    legacy.title_sealed, legacy.content_sealed = LEGACY_TITLE, LEGACY_BODY
    db.session.commit()
    services.evidence_path(legacy.evidence[0]).write_bytes(LEGACY_FILE)
    return {"enc": enc, "token": token, "legacy": legacy}


def hashing_url(s):
    return f"/admin/security-analysis/submissions/{s.id}/hashing"


def experiment_url(s):
    return f"/admin/security-analysis/submissions/{s.id}/hashing/experiments"


# ---------------------------------------------------------------------------
# A. Stored representations
# ---------------------------------------------------------------------------
class TestRepresentations:
    def test_envelope_and_payload_are_consistent(self, reports):
        enc = reports["enc"]
        envelope = sa.stored_text_envelope(enc.content_sealed)
        assert envelope == base64.urlsafe_b64decode(enc.content_sealed[3:])
        r = sa.stored_representations(envelope)
        parsed = sa.parse_package(envelope)
        assert r["payload"]["bytes"] == len(parsed.ciphertext)
        assert r["envelope"]["bytes"] == r["payload"]["bytes"] + sa.ENVELOPE_OVERHEAD == len(envelope)
        assert r["envelope"]["sha256"] == hashlib.sha256(envelope).hexdigest()
        assert r["payload"]["sha256"] == hashlib.sha256(parsed.ciphertext).hexdigest()
        assert r["payload"]["entropy"] == pytest.approx(sa.shannon_entropy(parsed.ciphertext))
        file_bytes = services.evidence_path(enc.evidence[0]).read_bytes()
        assert sa.stored_representations(file_bytes)["envelope"]["sha256"] == hashlib.sha256(file_bytes).hexdigest()

    def test_edge_cases(self):
        one = sa.representation_metrics(b"\x07")
        assert one["bytes"] == 1 and one["entropy"] == 0 and one["entropy_max"] == 0
        big = os.urandom(sa.MAX_STAT_BYTES + 1000)
        r = sa.representation_metrics(big)
        assert r["bytes_analysed"] == sa.MAX_STAT_BYTES                  # statistics capped...
        assert r["sha256"] == hashlib.sha256(big).hexdigest()            # ...the digest is not
        assert sa.stored_representations(b"not a package") is None
        assert sa.stored_text_envelope("plain legacy text") is None

    def test_report_page_shows_both_digests_admin_only(self, client, admin, journalist, reports):
        enc = reports["enc"]
        envelope = sa.stored_text_envelope(enc.content_sealed)
        envelope_digest = hashlib.sha256(envelope).hexdigest()
        payload_digest = hashlib.sha256(sa.parse_package(envelope).ciphertext).hexdigest()
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        page = client.get(f"/admin/security-analysis/submissions/{enc.id}").get_data(as_text=True)
        assert envelope_digest in page and payload_digest in page
        assert "not of the original report or file" in page and "Equality and linkability" in page
        audit = " ".join(f"{e.target} {e.detail}" for e in db.session.execute(db.select(AuditLog)).scalars())
        assert envelope_digest not in audit and payload_digest not in audit
        client.post("/auth/logout")
        login(client, journalist.username, JOURNALIST_PASSWORD)
        assert envelope_digest.encode() not in client.get(f"/journalist/submissions/{enc.id}").data

    def test_legacy_items_are_never_hashed_or_shown(self, client, admin, reports, monkeypatch):
        seen = []
        real = sa.representation_metrics
        monkeypatch.setattr(sa, "representation_metrics", lambda data, *a: (seen.append(bytes(data)), real(data, *a))[1])
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        page = client.get(f"/admin/security-analysis/submissions/{reports['legacy'].id}").get_data(as_text=True)
        assert seen == []
        assert "Stored unencrypted — not processed or hashed here." in page
        for marker in (LEGACY_TITLE, LEGACY_BODY, LEGACY_FILE[:17].decode()):
            assert marker not in page
        assert hashlib.sha256(LEGACY_FILE).hexdigest() not in page


# ---------------------------------------------------------------------------
# B. Isolated, bounded hash experiments
# ---------------------------------------------------------------------------
class TestWorker:
    TARGET = b"stored-envelope-stand-in|" * 120     # fixed: results are reproducible

    def job(self, **kw):
        base = {"kind": "preimage", "bits": 8, "budget": 16 * 256, "time_limit": 10,
                "data_b64": base64.b64encode(self.TARGET).decode()}
        return {**base, **kw}

    @pytest.mark.parametrize("kind", ["preimage", "second_preimage"])
    def test_matches_are_real_and_verified(self, kind):
        r = hash_worker.run(self.job(kind=kind, bits=12, budget=16 * 4096))
        assert r["found"] and r["outcome"] == "match found" and r["worker_verified"]
        candidate = hash_worker.candidate_for(kind, self.TARGET, bytes.fromhex(r["counter_hex"]))
        assert hashlib.sha256(candidate).hexdigest() == r["candidate_sha256"]
        assert hash_worker.truncate(hashlib.sha256(candidate).digest(), 12) == \
            hash_worker.truncate(hashlib.sha256(self.TARGET).digest(), 12)
        assert hash_jobs.verify_match(kind, 12, self.TARGET, r["counter_hex"])
        if kind == "second_preimage":
            assert r["differs_from_target"] and candidate != self.TARGET

    def test_budget_and_time_limits_are_honoured(self):
        r = hash_worker.run(self.job(bits=20, budget=10))
        assert r["attempts"] <= 10 and r["budget"] == 10
        if not r["found"]:
            assert r["outcome"] == "budget exhausted" and r["attempts"] == 10
        capped = hash_worker.run(self.job(bits=8, budget=10**9))
        assert capped["budget"] == 16 * 256                            # never above 16 * 2**t
        timed = hash_worker.run(self.job(bits=20, budget=16 * 2**20, time_limit=0))
        assert timed["found"] or timed["outcome"] == "time limit reached"

    def test_invalid_jobs_are_refused(self):
        for bad in ({"kind": "collision"}, {"bits": 0}, {"bits": 21}):
            with pytest.raises(ValueError):
                hash_worker.run(self.job(**bad))

    def test_independent_verification_rejects_wrong_claims(self):
        for kind in ("preimage", "second_preimage"):
            r = hash_worker.run(self.job(kind=kind, bits=16, budget=16 * 2**16))
            assert r["found"] and hash_jobs.verify_match(kind, 16, self.TARGET, r["counter_hex"])
            wrong = (int(r["counter_hex"], 16) + 1).to_bytes(8, "big").hex()
            assert not hash_jobs.verify_match(kind, 16, self.TARGET, wrong)            # wrong counter
            assert not hash_jobs.verify_match(kind, 16, self.TARGET[::-1], r["counter_hex"])  # other target
            assert not hash_jobs.verify_match(kind, 16, self.TARGET, "00")             # malformed counter

    def test_worker_is_standalone(self):
        tree = ast.parse(Path(hash_worker.__file__).read_text())
        imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        imported |= {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        assert imported <= {"base64", "hashlib", "json", "resource", "sys", "time"}


def fake_python(tmp_path, body: str) -> str:
    script = tmp_path / "fake-python"
    script.write_text("#!/bin/sh\n" + body + "\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


class TestJobManager:
    def submit(self, manager, admin_id=1, bits=8):
        return manager.submit(admin_id=admin_id, reference="submission:1", item_key="content", item_label="Report text",
                              representation="envelope", data=os.urandom(500), kind="preimage", bits=bits)

    def test_real_worker_process_end_to_end(self):
        m = hash_jobs.HashJobManager(cooldown=0)
        job = m.wait(self.submit(m))
        assert job["status"] == "done" and job["result"]["found"] and job["server_verified"] is True
        assert "data" not in job and "data_b64" not in str(job)              # no input bytes kept

    def test_queue_limit_and_cooldown(self):
        class Never:
            def submit(self, *a, **k):
                return None
        m = hash_jobs.HashJobManager(max_pending=1, cooldown=0)
        m._executor = Never()
        self.submit(m)
        with pytest.raises(hash_jobs.JobRejected):
            self.submit(m, admin_id=2)                                      # queue full
        c = hash_jobs.HashJobManager(cooldown=60)
        c._executor = Never()
        self.submit(c, admin_id=1)
        with pytest.raises(hash_jobs.JobRejected):
            self.submit(c, admin_id=1)                                      # same admin: cooldown
        self.submit(c, admin_id=2)                                          # another admin is fine

    def test_invalid_parameters(self):
        m = hash_jobs.HashJobManager(cooldown=0)
        with pytest.raises(ValueError):
            self.submit(m, bits=24)

    def test_wall_timeout_kills_the_worker(self, tmp_path):
        m = hash_jobs.HashJobManager(python=fake_python(tmp_path, "sleep 5"), cooldown=0, wall_timeout=0.5)
        job = m.wait(self.submit(m))
        assert job["status"] == "timed out" and job["result"] is None

    @pytest.mark.parametrize("body, error", [("exit 3", "worker exited with code 3"),
                                             ("echo not-json", "invalid worker output (JSONDecodeError)")])
    def test_worker_failures_are_reported_not_invented(self, tmp_path, body, error):
        m = hash_jobs.HashJobManager(python=fake_python(tmp_path, body), cooldown=0)
        job = m.wait(self.submit(m))
        assert job["status"] == "failed" and job["error"] == error and job["result"] is None


class TestExperimentEndpoint:
    def test_access_control(self, client, journalist, reports):
        url = experiment_url(reports["enc"])
        form = {"item": "content", "representation": "envelope", "kind": "preimage", "bits": "8"}
        assert "/auth/login" in client.post(url, data=form, follow_redirects=False).headers["Location"]
        login(client, journalist.username, JOURNALIST_PASSWORD)
        assert client.post(url, data=form, follow_redirects=False).status_code == 403
        assert client.get(url).status_code in (403, 405)

    def test_valid_request_runs_in_the_worker_and_is_audited(self, app, client, admin, reports):
        enc = reports["enc"]
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        response = client.post(experiment_url(enc), data={"item": "content", "representation": "envelope",
                                                          "kind": "second_preimage", "bits": "8"})
        assert response.status_code == 302 and response.headers["Location"].endswith("#experiments")
        manager = app.extensions["hash_jobs"]
        job = manager.wait(manager.jobs_for(enc.reference)[0]["id"])
        envelope = sa.stored_text_envelope(enc.content_sealed)
        assert job["status"] == "done" and job["server_verified"]
        assert hash_jobs.verify_match("second_preimage", 8, envelope, job["result"]["counter_hex"])
        event = db.session.execute(db.select(AuditLog).filter_by(action="analysis.hash_experiment")).scalar()
        assert event.target == enc.reference and event.detail == "content envelope second_preimage t=8"
        page = client.get(hashing_url(enc)).get_data(as_text=True)
        assert "worker ✓ server ✓" in page and "match found" in page
        assert "MARKER-B" not in page and reports["token"] not in page and enc.token_hash not in page

    @pytest.mark.parametrize("form", [
        {"item": "content", "representation": "envelope", "kind": "collision", "bits": "8"},
        {"item": "content", "representation": "envelope", "kind": "preimage", "bits": "64"},
        {"item": "content", "representation": "plaintext", "kind": "preimage", "bits": "8"},
        {"item": "evidence-999", "representation": "envelope", "kind": "preimage", "bits": "8"},
    ])
    def test_invalid_requests_start_nothing(self, app, client, admin, reports, form):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        client.post(experiment_url(reports["enc"]), data=form)
        assert "hash_jobs" not in app.extensions or not app.extensions["hash_jobs"].jobs_for(reports["enc"].reference)

    def test_legacy_items_cannot_be_targeted(self, app, client, admin, reports):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        page = client.post(experiment_url(reports["legacy"]), data={"item": "content", "representation": "envelope",
                                                                    "kind": "preimage", "bits": "8"},
                           follow_redirects=True).get_data(as_text=True)
        assert "Experiments run only on encrypted items" in page
        assert "hash_jobs" not in app.extensions or not app.extensions["hash_jobs"].jobs_for(reports["legacy"].reference)

    def test_csrf_is_required(self, tmp_path):
        app = create_app("testing", WTF_CSRF_ENABLED=True, EVIDENCE_DIR=str(tmp_path / "ev"),
                         SQLALCHEMY_DATABASE_URI=f"sqlite:///{tmp_path / 'csrf.db'}")
        with app.app_context():
            db.create_all()
            create_admin(ADMIN_USERNAME, ADMIN_PASSWORD, must_change_password=False)
            submission, _ = services.create_submission("t", "b")
            sid = submission.id
        client = app.test_client()
        token = re.search(rb'name="csrf_token"[^>]*value="([^"]+)"', client.get("/auth/login").data).group(1).decode()
        client.post("/auth/login", data={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD, "csrf_token": token})
        response = client.post(f"/admin/security-analysis/submissions/{sid}/hashing/experiments",
                               data={"item": "content", "representation": "envelope", "kind": "preimage", "bits": "8"})
        assert response.status_code == 400
        assert "hash_jobs" not in app.extensions


# ---------------------------------------------------------------------------
# C. Digital-signature experiment
# ---------------------------------------------------------------------------
class TestSignatureExperiment:
    def test_rsa_pss_behaves_as_expected(self):
        r = signature_analysis.rsa_pss_experiment(key_bits=2048, runs=5)
        assert r["all_checks_passed"] and all(r["checks"].values()) and len(r["checks"]) == 6
        assert r["signature_bytes"] == 256 and r["sign_ms"] > 0 and r["verify_ms"] > 0
        assert not any("private" in str(k).lower() for k in r)               # no private key returned
        assert all(isinstance(v, (int, float, str, bool, dict)) for v in r.values())

    def test_experiments_page_shows_the_signature_section(self, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        page = client.get("/admin/security-analysis/experiments").get_data(as_text=True)
        assert "Digital signature experiment (RSA-PSS)" in page and "The app does not sign submissions" in page
        assert "Wrong public key rejected" in page and "BEGIN" not in page and "PRIVATE" not in page


# ---------------------------------------------------------------------------
# D. Corrected controlled-experiment methodology and labels
# ---------------------------------------------------------------------------
class TestCorrectedExperiments:
    def test_nonce_controls_show_randomization_not_sensitivity(self):
        t = sa.text_experiments(trials=16)
        a = t["avalanche"]
        assert a["fixed_nonce_ciphertext_pct"] == pytest.approx(100 / (t["sample_bytes"] * 8))
        assert abs(a["production_package_pct"] - a["fresh_nonce_same_plaintext_pct"]) < 2
        assert 45 < a["fresh_nonce_same_plaintext_pct"] < 55
        i = sa.image_experiments()
        same, one = i["npcr_uaci"]["same_image_fresh_nonce"], i["npcr_uaci"]["production_fresh_nonce"]
        assert 99 < same[0] < 100 and abs(same[0] - one[0]) < 0.5

    def test_pages_present_fixed_nonce_as_a_diagnostic(self, client, admin, reports):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        for url in ("/admin/security-analysis/experiments", f"/admin/security-analysis/submissions/{reports['enc'].id}"):
            page = client.get(url).get_data(as_text=True)
            assert "Controlled diagnostic (fixed nonce)" in page
            assert "Not a cryptographic security score" in page
            assert "Ideal ≈ 99.61 %" not in page
        experiments = client.get("/admin/security-analysis/experiments").get_data(as_text=True)
        assert "Control:</strong> the same plaintext twice" in experiments
        assert "Control:</strong> the same image twice" in experiments
        assert "Image input format and transformations" in experiments
