"""Hashing analysis (admin only): methodology, toy attacks, isolation from real data."""

from __future__ import annotations

import ast
import base64
import hashlib
import math
from pathlib import Path

import pytest

from phase2.extensions import db
from phase2.models import AuditLog
from submissions import hash_analysis as ha
from submissions import security_analysis as sa
from submissions import services
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, JOURNALIST_PASSWORD, login

URL = "/admin/security-analysis/hashing"


def copy_prefix(message: bytes) -> bytes:
    """A deliberately terrible 'hash': the first 32 bytes of the input."""
    return (message + bytes(32))[:32]


def xor_fold(message: bytes) -> bytes:
    """A linear 'hash': XOR of 32-byte blocks (one input bit flips one output bit)."""
    out = bytearray(32)
    for i, byte in enumerate(message):
        out[i % 32] ^= byte
    return bytes(out)


class TestMethodology:
    def test_sha256_is_consistent_with_an_ideal_hash(self):
        r = ha.strict_avalanche()
        assert r["consistent"] is True
        assert abs(r["z_mean"]) < 3 and r["chi_square_p"] >= 0.001
        assert abs(r["phi_z"]) < 4
        assert abs(r["distance"]["mean"] - 128) < 1 and abs(r["distance"]["sd"] - 8) < 0.5

    @pytest.mark.parametrize("weak", [copy_prefix, xor_fold])
    def test_weak_functions_are_detected(self, weak):
        r = ha.strict_avalanche(hash_fn=weak)
        assert r["consistent"] is False
        assert abs(r["z_mean"]) > 100 and r["chi_square_p"] < 1e-6

    def test_modified_messages_change_about_half_the_digest(self):
        for row in ha.modification_analysis(samples=400):
            assert abs(row["z_mean"]) < 4, row["modification"]
            assert abs(row["phi_z"]) < 4, row["modification"]
            assert row["pairs"] == 400

    def test_weak_function_fails_the_modification_analysis(self):
        rows = {r["modification"]: r for r in ha.modification_analysis(hash_fn=xor_fold, samples=200)}
        assert rows["one bit flipped"]["mean"] == 1  # a linear map: exactly one output bit changes

    def test_chi_square_p_value_approximation(self):
        assert ha.chi_square_p_value(256, 256) == pytest.approx(0.49, abs=0.02)
        assert ha.chi_square_p_value(330, 256) < 0.01
        assert ha.chi_square_p_value(200, 256) > 0.99

    def test_results_are_reproducible_with_the_fixed_seed(self):
        a, b = ha.strict_avalanche(), ha.strict_avalanche()
        assert a["mean_flip_rate"] == b["mean_flip_rate"] and a["chi_square"] == b["chi_square"]
        assert ha.strict_avalanche(seed=1)["chi_square"] != a["chi_square"]


class TestToyAttacks:
    def test_preimage_toy_finds_matching_truncated_digests(self):
        r = ha.preimage_toy(bits_list=(8, 12), trials={8: 16, 12: 4})
        for row in r["rows"]:
            assert row["found"] == row["trials"]
            assert row["expected_attempts"] == 2 ** row["bits"]
        ex = r["rows"][0]["example"]
        found_digest = hashlib.sha256(bytes.fromhex(ex["found"])).digest()
        assert found_digest[0] == int(ex["target"], 16)          # first 8 bits match
        assert found_digest.hex() == ex["found_digest"] != ex["secret_digest"]
        assert r["full_log10_years"] > 50                         # full SHA-256 is out of reach

    def test_second_preimage_toy_finds_a_different_message(self):
        r = ha.second_preimage_toy(bits_list=(8,), trials={8: 16})
        row = r["rows"][0]
        assert row["found"] == 16
        ex = row["example"]
        assert ex["m1"] != ex["m2"] and ex["full_m1"] != ex["full_m2"]
        assert ex["full_m1"][:2] == ex["full_m2"][:2] == ex["truncated"]

    def test_mean_attempts_scale_like_two_to_the_t(self):
        r = ha.preimage_toy()
        for row in r["rows"]:
            assert row["within_expected"], row["bits"]

    def test_restricted_space_is_brute_forced(self):
        r = ha.restricted_space_demo()
        assert r["correct"] is True and r["attempts"] <= 10_000
        assert r["token_bits"] == 192 and r["token_log10_candidates"] == pytest.approx(192 * math.log10(2))


class TestIsolation:
    def test_module_imports_nothing_that_can_reach_real_data(self):
        source = Path(ha.__file__).read_text()
        imported = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                imported |= {alias.name for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
        assert imported <= {"__future__", "hashlib", "math", "random", "statistics", "time", "typing"}

    def test_page_access(self, client, admin, journalist):
        assert "/auth/login" in client.get(URL, follow_redirects=False).headers["Location"]
        login(client, journalist.username, JOURNALIST_PASSWORD)
        assert client.get(URL, follow_redirects=False).status_code == 403
        client.post("/auth/logout")
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert client.get(URL).status_code == 200

    def test_page_shows_every_section_and_is_audited(self, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        page = client.get(URL).get_data(as_text=True)
        for text in ("Hash correlation (strict avalanche criterion)", "Digest bit difference for modified messages",
                     "Preimage resistance — bounded toy example", "Second-preimage resistance — bounded toy example",
                     "Restricted candidate space", "HMAC-SHA-256", "AES-GCM authentication tag",
                     "Digital signature", "do not prove SHA-256 is secure", "Limitations"):
            assert text in page, text
        assert "No evidence of deviation" in page and "could not be computed" not in page
        event = db.session.execute(db.select(AuditLog).filter_by(action="analysis.viewed", target="hashing")).scalar()
        assert event is not None and event.detail is None

    def test_page_exposes_no_real_values_or_keys(self, app, client, admin):
        submission, token = services.create_submission("Secret title MARKER-T", "Secret body MARKER-B")
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        page = client.get(URL).get_data(as_text=True)
        for real in (token, submission.token_hash, submission.title_sealed[3:40],
                     submission.content_sealed[3:40], "MARKER-T", "MARKER-B"):
            assert real not in page
        keys = app.extensions["phase5_keys"]
        for key in (keys.encryption, keys.mac):
            assert key.hex() not in page and base64.urlsafe_b64encode(key).decode().rstrip("=") not in page

    def test_overview_links_to_the_hashing_page(self, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert f'href="{URL}"' in client.get("/admin/security-analysis").get_data(as_text=True)


# ---------------------------------------------------------------------------
# Refined methodology and per-item inputs
# ---------------------------------------------------------------------------
def duplicated_half(message: bytes) -> bytes:
    """Perfectly balanced but dependent output: the second half repeats the first."""
    return hashlib.sha256(message).digest()[:16] * 2


class TestRefinedMethodology:
    def test_independence_test_catches_dependent_output_bits(self):
        r = ha.strict_avalanche(hash_fn=duplicated_half)
        assert abs(r["mean_flip_rate"] - 0.5) < 0.01          # the balance test alone would pass it
        assert "independence" in r["rejected"] and r["outcome"] == "deviation flagged"

    def test_sha256_passes_all_four_tests(self):
        r = ha.strict_avalanche()
        assert r["rejected"] == [] and r["outcome"] == "no evidence of deviation"
        assert set(r["p_values"]) == {"balance", "per_bit", "independence", "relation"}

    def test_input_avalanche_on_given_bytes(self):
        r = ha.input_avalanche(bytes(range(256)) * 16)
        assert r["trials"] == 256 and r["outcome"] == "no evidence of deviation" and not r["capped"]

    def test_input_avalanche_caps_large_inputs(self):
        r = ha.input_avalanche(b"\x5a" * (3 * 1024 * 1024))
        assert r["bytes_analysed"] == ha.INPUT_CAP and r["bytes_total"] == 3 * 1024 * 1024 and r["capped"]

    def test_tiny_inputs_are_not_judged(self):
        r = ha.input_avalanche(b"abc")
        assert r["trials"] == 24 and r["outcome"] == "too few flips to judge" and r["consistent"] is False
        with pytest.raises(ValueError):
            ha.input_avalanche(b"")

    def test_no_digest_of_the_input_is_returned(self):
        data = b"stored-ciphertext-stand-in" * 40
        assert hashlib.sha256(data).hexdigest() not in repr(ha.input_avalanche(data))

    def test_sized_synthetic_messages(self):
        r = ha.sized_modification_analysis(20_000, samples=20)
        assert r["message_bytes"] == ha.SIZED_CAP and r["capped"]
        short = {row["modification"]: row["pairs"] for row in ha.sized_modification_analysis(2, samples=10)["rows"]}
        assert short["two adjacent words swapped"] == 0 and short["one bit flipped"] == 10


# ---------------------------------------------------------------------------
# Per-report page
# ---------------------------------------------------------------------------
LEGACY_TITLE, LEGACY_BODY = "LEGACY-TITLE-PLAINTEXT", "LEGACY-BODY-PLAINTEXT"
LEGACY_FILE = b"LEGACY-EVIDENCE-PLAINTEXT" * 8


def report_url(submission):
    return f"/admin/security-analysis/submissions/{submission.id}/hashing"


@pytest.fixture()
def reports(app):
    import io
    from PIL import Image
    buffer = io.BytesIO()
    Image.effect_noise((48, 48), 50).convert("RGB").save(buffer, format="PNG")
    encrypted, token = services.create_submission("Hashing title MARKER-T", "Hashing body MARKER-B", ("png", buffer.getvalue()))
    legacy, _ = services.create_submission("x", "x", ("txt", b"placeholder"))
    legacy.title_sealed, legacy.content_sealed = LEGACY_TITLE, LEGACY_BODY
    db.session.commit()
    services.evidence_path(legacy.evidence[0]).write_bytes(LEGACY_FILE)
    missing, _ = services.create_submission("y", "y", ("txt", b"gone"))
    services.evidence_path(missing.evidence[0]).rename(services.evidence_path(missing.evidence[0]).with_suffix(".moved"))
    return {"encrypted": encrypted, "token": token, "legacy": legacy, "missing": missing}


class TestPerReportPage:
    def test_access(self, client, admin, journalist, reports):
        url = report_url(reports["encrypted"])
        assert "/auth/login" in client.get(url, follow_redirects=False).headers["Location"]
        login(client, journalist.username, JOURNALIST_PASSWORD)
        assert client.get(url, follow_redirects=False).status_code == 403
        client.post("/auth/logout")
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert client.get(url).status_code == 200
        assert client.get("/admin/security-analysis/submissions/99999/hashing").status_code == 404

    def test_every_report_is_listed_and_viewable(self, client, admin, reports):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        listing = client.get(URL).get_data(as_text=True)
        for key in ("encrypted", "legacy", "missing"):
            assert f'href="{report_url(reports[key])}"' in listing
            assert client.get(report_url(reports[key])).status_code == 200
        assert "Legacy (unencrypted)" in listing and "File missing" in listing

    def test_encrypted_report_is_analysed_as_ciphertext(self, client, admin, reports):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        page = client.get(report_url(reports["encrypted"])).get_data(as_text=True)
        assert page.count("No evidence of deviation") >= 3            # title, text, evidence
        assert "Ciphertext analysis" in page and "Synthetic messages" in page
        assert "Plaintext analysis:</strong> none" in page
        assert "not a security score for this report" in page
        assert page.count('<span class="badge badge-encrypted">matches</span>') == 3
        assert "Not verified here" in page and "isolated worker process" in page

    def test_legacy_and_missing_items_are_not_processed(self, client, admin, reports, monkeypatch):
        seen = []
        real = ha.input_avalanche
        monkeypatch.setattr(ha, "input_avalanche", lambda data, *a, **k: (seen.append(bytes(data)), real(data, *a, **k))[1])
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        page = client.get(report_url(reports["legacy"])).get_data(as_text=True)
        assert page.count("Not analysed: stored unencrypted") >= 3
        for marker in (LEGACY_TITLE, LEGACY_BODY, LEGACY_FILE[:24].decode()):
            assert marker not in page
        assert seen == []                    # every item is unencrypted: nothing was hashed at all
        assert "the stored file is missing" in client.get(report_url(reports["missing"])).get_data(as_text=True)

    def test_no_plaintext_secrets_or_authentication_values(self, app, client, admin, reports):
        enc = reports["encrypted"]
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        page = client.get(report_url(enc)).get_data(as_text=True)
        assert "MARKER-T" not in page and "MARKER-B" not in page
        assert reports["token"] not in page and enc.token_hash not in page
        for value in (enc.title_sealed, enc.content_sealed):
            parsed = sa.analyse_stored_text(value)["parsed"]
            assert value[3:60] not in page
            assert parsed.tag.hex() not in page and parsed.mac.hex() not in page
            package = base64.urlsafe_b64decode(value[3:])
            assert hashlib.sha256(package).hexdigest() not in page                 # no fingerprint shown
            assert hashlib.sha256(parsed.ciphertext).hexdigest() not in page
        keys = app.extensions["phase5_keys"]
        for key in (keys.encryption, keys.mac):
            assert key.hex() not in page and base64.urlsafe_b64encode(key).decode().rstrip("=") not in page

    def test_header_time_mismatch_is_reported_without_a_key(self, client, admin, reports):
        enc = reports["encrypted"]
        package = bytearray(base64.urlsafe_b64decode(enc.content_sealed[3:]))
        package[10] ^= 0x01                                     # last byte of the protected timestamp
        enc.content_sealed = "p5:" + base64.urlsafe_b64encode(bytes(package)).decode()
        db.session.commit()
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        page = client.get(report_url(enc)).get_data(as_text=True)
        assert '<span class="badge badge-problem">differs</span>' in page

    def test_integrity_history_is_shown_as_history_only(self, client, admin, reports):
        enc = reports["encrypted"]
        db.session.add(AuditLog(action="submission.integrity_failed", target=enc.reference, detail="hmac"))
        db.session.commit()
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        page = client.get(report_url(enc)).get_data(as_text=True)
        assert "Recorded integrity failures for this report: 1." in page
        assert "not a current verification" in page and "not that the data is intact now" in page

    def test_view_is_audited_with_reference_only(self, client, admin, reports):
        enc = reports["encrypted"]
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        client.get(report_url(enc))
        event = db.session.execute(db.select(AuditLog).filter_by(action="analysis.viewed", target=enc.reference,
                                                                  detail="hashing")).scalar()
        assert event is not None

    def test_report_page_links_to_its_hashing_analysis(self, client, admin, reports):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        page = client.get(f"/admin/security-analysis/submissions/{reports['encrypted'].id}").get_data(as_text=True)
        assert f'href="{report_url(reports["encrypted"])}"' in page
