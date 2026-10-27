"""Security-analysis feature: metric correctness, ciphertext-only handling of
real records, admin-only access, auditing, and no change to stored data."""

from __future__ import annotations

import base64
import hashlib
import math
import os
import re

import pytest

from submissions import crypto
from submissions import security_analysis as sa


# ---------------------------------------------------------------------------
# 1. Metrics against known answers
# ---------------------------------------------------------------------------
class TestMetrics:
    def test_entropy_bounds(self):
        assert sa.shannon_entropy(b"") is None  # no data -> no value, never a made-up 0
        assert sa.shannon_entropy(b"A" * 1000) == 0
        assert sa.shannon_entropy(bytes(range(256)) * 4) == pytest.approx(8.0)
        assert sa.shannon_entropy(b"ab" * 50) == pytest.approx(1.0)
        assert sa.max_entropy_for_length(16) == pytest.approx(4.0)
        assert sa.max_entropy_for_length(10_000) == 8.0

    def test_no_data_gives_no_value(self):
        """Empty input has no defined result: None (shown as n/a), not 0 or 1."""
        assert sa.chi_square_uniform(b"") is None
        assert sa.bit_difference(b"", b"") is None
        assert sa.npcr_uaci(b"", b"") == (None, None)
        assert sa.mse(b"", b"") is None and sa.psnr(None) is None
        assert sa.ssim(bytes(16), bytes(16), 4, 4) is None  # smaller than one 8x8 window

    def test_chi_square_of_uniform_bytes_is_zero(self):
        assert sa.chi_square_uniform(bytes(range(256)) * 10) == pytest.approx(0)
        assert sa.chi_square_uniform(b"\x00" * 2560) > 600_000

    def test_pearson(self):
        assert sa.pearson([1, 2, 3, 4], [2, 4, 6, 8]) == pytest.approx(1)
        assert sa.pearson([1, 2, 3, 4], [8, 6, 4, 2]) == pytest.approx(-1)
        assert sa.pearson([5, 5, 5], [1, 2, 3]) is None  # constant -> undefined

    def test_bit_difference(self):
        assert sa.bit_difference(b"\x00\x00", b"\x00\x00") == 0
        assert sa.bit_difference(b"\x00", b"\xff") == 100
        assert sa.bit_difference(b"\x00\x00", b"\x01\x00") == pytest.approx(100 / 16)

    def test_npcr_uaci_known_values(self):
        assert sa.npcr_uaci(b"\x10" * 100, b"\x10" * 100) == (0.0, 0.0)
        npcr, uaci = sa.npcr_uaci(b"\x00" * 100, b"\xff" * 100)
        assert npcr == 100 and uaci == pytest.approx(100)
        npcr, uaci = sa.npcr_uaci(b"\x00" * 4, b"\x00\x00\x00\xff")
        assert npcr == 25 and uaci == pytest.approx(25)

    def test_mse_psnr_ssim_identical_and_different(self):
        img = bytes((x * 7 + y * 3) % 256 for y in range(32) for x in range(32))
        assert sa.mse(img, img) == 0 and math.isinf(sa.psnr(0))
        assert sa.ssim(img, img, 32, 32) == pytest.approx(1)
        noisy = bytes((v + 40) % 256 for v in img)
        assert sa.mse(img, noisy) > 0 and sa.psnr(sa.mse(img, noisy)) < 30
        assert sa.ssim(img, noisy, 32, 32) < 1
        assert sa.psnr(1) == pytest.approx(10 * math.log10(255 ** 2))

    def test_image_correlation_of_smooth_vs_random(self):
        smooth = bytes(min(255, x * 4) for _ in range(64) for x in range(64))
        corr = sa.image_correlations(smooth, 64, 64)
        assert corr["horizontal"] > 0.99
        noise = sa.image_correlations(os.urandom(64 * 64), 64, 64)
        assert all(abs(v) < 0.1 for v in noise.values())


class TestParsing:
    KEYS = crypto.Keys(os.urandom(32), os.urandom(32))

    def _sealed(self, plaintext=b"hello world"):
        from datetime import datetime
        return crypto.seal(self.KEYS, plaintext, purpose="p", binding="b",
                           timestamp=datetime(2026, 1, 1, 12, 0, 0, 123456))

    def test_package_parts_without_any_key(self):
        package = self._sealed(b"x" * 50)
        parsed = sa.parse_package(package)
        assert parsed.version == 1 and parsed.package_size == len(package)
        assert len(parsed.nonce) == 12 and len(parsed.tag) == 16 and len(parsed.mac) == 32
        assert len(parsed.ciphertext) == 50
        assert parsed.timestamp.microsecond == 123456

    def test_non_packages_are_rejected(self):
        assert sa.parse_package(b"short") is None
        assert sa.parse_package(b"XX" + bytes(100)) is None

    def test_legacy_plaintext_text_is_withheld(self):
        result = sa.analyse_stored_text("A plaintext report from before Phase 5")
        assert result == {"state": "legacy"}  # nothing from the plaintext value is returned

    def test_malformed_text(self):
        assert sa.analyse_stored_text("p5:!!!not-base64")["state"] == "malformed"
        bad = "p5:" + base64.urlsafe_b64encode(b"XX" + bytes(80)).decode()
        assert sa.analyse_stored_text(bad)["state"] == "malformed"

    def test_encrypted_text_is_analysed(self):
        value = "p5:" + base64.urlsafe_b64encode(self._sealed()).decode()
        result = sa.analyse_stored_text(value)
        assert result["state"] == "encrypted" and "stored_value" not in result
        # only the ciphertext body is offered for display -- not the GCM tag or HMAC
        assert base64.urlsafe_b64decode(result["ciphertext_b64"]) == result["parsed"].ciphertext
        assert result["stats"]["bytes_total"] == len(b"hello world")

    def test_files(self):
        assert sa.analyse_stored_file(None) == {"state": "missing"}
        assert sa.analyse_stored_file(b"\x89PNG\r\n\x1a\n" + bytes(50)) == {"state": "legacy"}
        assert sa.analyse_stored_file(self._sealed(os.urandom(5000)))["state"] == "encrypted"

    def test_cipher_image_reads_only(self):
        data = os.urandom(70_000)
        before = hashlib.sha256(data).hexdigest()
        png, side, used = sa.cipher_image_png(data)
        assert png.startswith(b"\x89PNG") and side == 256 and used == 65_536
        assert hashlib.sha256(data).hexdigest() == before
        assert sa.cipher_image_png(os.urandom(100))[1] == 10
        with pytest.raises(ValueError):
            sa.cipher_image_png(b"")


class TestExperiments:
    """Controlled experiments give the values the construction implies."""

    def test_text_experiments(self):
        r = sa.text_experiments(trials=16)
        assert r["entropy"]["ciphertext"] > 7.8 > r["entropy"]["plaintext"]
        # AES-GCM is CTR-based: with the nonce fixed, one plaintext bit -> one ciphertext bit.
        assert r["avalanche"]["fixed_nonce_ciphertext_pct"] == pytest.approx(100 / (2048 * 8))
        assert 40 < r["avalanche"]["fixed_nonce_tag_pct"] < 60
        assert 45 < r["avalanche"]["production_package_pct"] < 55
        assert 45 < r["key_sensitivity"]["ciphertext_pct_after_1bit_key_flip"] < 55
        assert 45 < r["key_sensitivity"]["mac_pct_after_1bit_key_flip"] < 55
        assert r["key_sensitivity"]["decryption_rejected_wrong_enc_key"] == 16
        assert r["key_sensitivity"]["decryption_rejected_wrong_mac_key"] == 16
        assert abs(r["correlation"]["plaintext_vs_ciphertext"]) < 0.1

    def test_image_experiments(self):
        r = sa.image_experiments()
        assert r["entropy"]["cipher"] > 7.9 > r["entropy"]["plain"]
        assert r["correlation"]["plain"]["horizontal"] > 0.8
        assert all(abs(v) < 0.1 for v in r["correlation"]["cipher"].values())
        fixed_npcr, _ = r["npcr_uaci"]["fixed_nonce"]
        assert fixed_npcr == pytest.approx(100 / r["bytes"])  # one value of one pixel changed
        fresh_npcr, fresh_uaci = r["npcr_uaci"]["production_fresh_nonce"]
        assert 99 < fresh_npcr < 100 and 32 < fresh_uaci < 35
        assert r["key_sensitivity"]["wrong_key_rejected"] is True
        assert 99 < r["key_sensitivity"]["npcr"] < 100
        quality = r["quality"]
        roundtrip = quality["original vs decrypted (encrypt/decrypt round trip)"]
        assert roundtrip["mse"] == 0 and math.isinf(roundtrip["psnr"]) and roundtrip["ssim"] == 1
        jpeg = quality["uploaded JPEG vs metadata-scrubbed JPEG (re-encoded, quality 95)"]
        assert jpeg["psnr"] > 35 and jpeg["ssim"] > 0.95

    def test_experiments_never_use_production_keys(self, app, monkeypatch):
        from submissions import services

        monkeypatch.setattr(services, "protection_keys",
                            lambda: pytest.fail("production keys used by an experiment"))
        sa.text_experiments(trials=4)
        sa.image_experiments()
        sa.performance([("1 KB", 1000)], runs=2)

    def test_performance_rows(self):
        rows = sa.performance([("empty", 0), ("1 KB", 1000)], runs=3)
        assert rows[1]["bytes"] == 1000 and rows[1]["package_bytes"] == 1000 + 71
        assert rows[1]["encrypt_ms"] > 0 and rows[1]["encrypt_mb_s"] > 0
        assert rows[0]["encrypt_mb_s"] is None  # no throughput for zero bytes


# ---------------------------------------------------------------------------
# 2. Admin pages: access, ciphertext only, legacy withheld, audited, read-only
# ---------------------------------------------------------------------------
from phase2.extensions import db  # noqa: E402
from phase2.models import AuditLog  # noqa: E402
from submissions import services  # noqa: E402
from submissions.models import Submission  # noqa: E402
from tests.conftest import (  # noqa: E402
    ADMIN_PASSWORD, ADMIN_USERNAME, JOURNALIST_PASSWORD, login,
)

TITLE = "Harbour bribery title marker"
BODY = "Secret report body marker: payments on 3 March."
LEGACY_TITLE = "LEGACY-PLAINTEXT-TITLE"
LEGACY_BODY = "LEGACY-PLAINTEXT-BODY"
LEGACY_FILE = b"LEGACY-PLAINTEXT-EVIDENCE-FILE" * 10


def _png() -> bytes:
    import io
    from PIL import Image
    buffer = io.BytesIO()
    Image.effect_noise((64, 64), 60).convert("RGB").save(buffer, format="PNG")
    return buffer.getvalue()


@pytest.fixture()
def stored(app):
    """One encrypted report with evidence, one legacy (pre-Phase-5) report
    with a legacy plaintext evidence file, and one with its file missing."""
    encrypted, _ = services.create_submission(TITLE, BODY, ("png", _png()))
    legacy, _ = services.create_submission("x", "x", ("txt", b"placeholder"))
    legacy.title_sealed, legacy.content_sealed = LEGACY_TITLE, LEGACY_BODY
    db.session.commit()
    services.evidence_path(legacy.evidence[0]).write_bytes(LEGACY_FILE)
    missing, _ = services.create_submission("y", "y", ("txt", b"gone"))
    services.evidence_path(missing.evidence[0]).unlink()
    return encrypted, legacy, missing


def _urls(encrypted, legacy, missing):
    return [
        "/admin/security-analysis",
        f"/admin/security-analysis/submissions/{encrypted.id}",
        f"/admin/security-analysis/submissions/{legacy.id}",
        f"/admin/security-analysis/submissions/{missing.id}",
        f"/admin/security-analysis/submissions/{encrypted.id}/evidence/{encrypted.evidence[0].id}/cipher.png",
        "/admin/security-analysis/experiments",
    ]


def _no_real_decryption(app, monkeypatch):
    """Fail if any real-data decryption path or the production keys are used."""
    for name in ("open_report", "open_title", "try_open_title", "read_evidence_file"):
        monkeypatch.setattr(services, name, lambda *a, _n=name, **k: pytest.fail(f"{_n} called"))
    production = app.extensions["phase5_keys"]
    real_open = crypto.open_package

    def guarded(keys, *args, **kwargs):
        assert keys.encryption != production.encryption and keys.mac != production.mac, \
            "production keys used"
        return real_open(keys, *args, **kwargs)

    monkeypatch.setattr(crypto, "open_package", guarded)


class TestAdminPages:
    def test_anonymous_is_redirected_to_login(self, client, stored):
        for url in _urls(*stored):
            response = client.get(url, follow_redirects=False)
            assert response.status_code == 302 and "/auth/login" in response.headers["Location"]

    def test_journalist_is_forbidden(self, client, journalist, stored):
        login(client, journalist.username, JOURNALIST_PASSWORD)
        for url in _urls(*stored):
            assert client.get(url, follow_redirects=False).status_code == 403

    def test_admin_sees_ciphertext_never_plaintext(self, app, client, admin, stored, monkeypatch):
        _no_real_decryption(app, monkeypatch)
        encrypted, legacy, missing = stored
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        for url in _urls(*stored):
            response = client.get(url)
            assert response.status_code == 200, url
            assert "no-store" in response.headers["Cache-Control"]
            for marker in (TITLE, BODY, LEGACY_TITLE, LEGACY_BODY):
                assert marker.encode() not in response.data, (url, marker)
            assert LEGACY_FILE[:30] not in response.data

        page = client.get(f"/admin/security-analysis/submissions/{encrypted.id}").get_data(as_text=True)
        # Only the ciphertext body is shown; the full stored value (which contains
        # the GCM tag and HMAC) and the authentication values themselves are not.
        for value in (encrypted.title_sealed, encrypted.content_sealed):
            parsed = sa.analyse_stored_text(value)
            assert parsed["ciphertext_b64"] in page
            assert value not in page
            assert parsed["parsed"].tag.hex() not in page and parsed["parsed"].mac.hex() not in page
        assert "value hidden" in page
        assert "Not applicable" not in page and "Statistics do not prove security" in page
        assert "This report" in page and "Synthetic experiment" in page

    def test_legacy_and_missing_records_are_handled(self, client, admin, stored):
        encrypted, legacy, missing = stored
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        page = client.get(f"/admin/security-analysis/submissions/{legacy.id}").get_data(as_text=True)
        assert "Legacy unencrypted record: stored value withheld" in page
        assert "Legacy unencrypted file: withheld" in page
        legacy_png = (f"/admin/security-analysis/submissions/{legacy.id}"
                      f"/evidence/{legacy.evidence[0].id}/cipher.png")
        assert client.get(legacy_png).status_code == 404
        page = client.get(f"/admin/security-analysis/submissions/{missing.id}").get_data(as_text=True)
        assert "evidence file is missing" in page
        missing_png = (f"/admin/security-analysis/submissions/{missing.id}"
                       f"/evidence/{missing.evidence[0].id}/cipher.png")
        assert client.get(missing_png).status_code == 404
        overview = client.get("/admin/security-analysis").get_data(as_text=True)
        assert "Legacy (unencrypted)" in overview and "File missing" in overview

    def test_cipher_image_is_the_stored_ciphertext(self, client, admin, stored):
        from PIL import Image
        import io

        encrypted, legacy, _ = stored
        evidence = encrypted.evidence[0]
        raw = services.evidence_path(evidence).read_bytes()
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        response = client.get(f"/admin/security-analysis/submissions/{encrypted.id}"
                              f"/evidence/{evidence.id}/cipher.png")
        assert response.mimetype == "image/png"
        image = Image.open(io.BytesIO(response.data))
        side = image.size[0]
        assert image.mode == "RGB"                          # a PNG upload: drawn as colour noise
        assert image.tobytes() == sa.parse_package(raw).ciphertext[:side * side * 3]
        # Evidence must belong to the submission in the URL.
        wrong = f"/admin/security-analysis/submissions/{legacy.id}/evidence/{evidence.id}/cipher.png"
        assert client.get(wrong).status_code == 404
        assert client.get("/admin/security-analysis/submissions/99999").status_code == 404

    def test_page_views_are_audited_without_content(self, client, admin, stored):
        encrypted, _, _ = stored
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        for url in _urls(*stored):
            client.get(url)
        events = db.session.execute(
            db.select(AuditLog).where(AuditLog.action == "analysis.viewed")).scalars().all()
        targets = {e.target for e in events}
        assert {"overview", "experiments", encrypted.reference} <= targets
        assert all(e.actor_username == ADMIN_USERNAME for e in events)
        everything = " ".join(f"{e.target} {e.detail}" for e in
                              db.session.execute(db.select(AuditLog)).scalars())
        for secret in (TITLE, BODY, LEGACY_TITLE, encrypted.content_sealed[3:40]):
            assert secret not in everything

    def test_viewing_changes_no_record_or_file(self, client, admin, stored):
        def snapshot():
            db.session.expire_all()
            rows = [(s.id, s.title_sealed, s.content_sealed, s.status, s.updated_at,
                     [(e.stored_name, e.extension, e.size_bytes) for e in s.evidence])
                    for s in db.session.execute(db.select(Submission)).scalars()]
            files = sorted((p.name, hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns)
                           for p in services.evidence_dir().iterdir())
            return rows, files

        before = snapshot()
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        for url in _urls(*stored):
            client.get(url)
        assert snapshot() == before

    def test_analysis_error_is_shown_not_raised(self, client, admin, stored, monkeypatch):
        encrypted, _, _ = stored

        def boom(*_):
            raise RuntimeError("synthetic failure")

        monkeypatch.setattr(sa, "analyse_stored_text", boom)
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        response = client.get(f"/admin/security-analysis/submissions/{encrypted.id}")
        assert response.status_code == 200
        assert b"could not be computed" in response.data
        assert b"synthetic failure" not in response.data

    def test_nav_and_existing_admin_pages_still_work(self, client, admin, stored):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        for page in ("/admin/dashboard", "/admin/audit", "/admin/journalists"):
            response = client.get(page)
            assert response.status_code == 200
            assert b"/admin/security-analysis" in response.data


# ---------------------------------------------------------------------------
# 3. All 13 metrics show a real number, with an honest source label
# ---------------------------------------------------------------------------
TEXT_METRICS = ["Entropy", "Avalanche effect", "Frequency analysis", "Correlation", "Key sensitivity"]
IMAGE_METRICS = ["Histogram", "Entropy", "Pixel correlation", "NPCR", "UACI", "Key sensitivity",
                 "MSE / PSNR", "SSIM"]
SYNTHETIC = {"Avalanche effect", "Key sensitivity", "NPCR", "UACI", "MSE / PSNR", "SSIM"}
NUMBER = re.compile(r"(?<![\w.])(-?\d+\.\d+|\d+/\d+|∞)")
ROW = re.compile(r'<th scope="row" data-label="Metric">([^<]+)(.*?)</th>\s*'
                 r'<td data-label="Result" class="metric-result">(.*?)<td data-label="What it means"', re.S)


def metric_rows(html: str) -> list[tuple[str, str, str]]:
    return [(name.strip(), label, result) for name, label, result in ROW.findall(html)]


def assert_numeric(rows):
    for name, _, result in rows:
        assert NUMBER.search(result), f"{name}: no numerical result"
        for placeholder in ("n/a", "Not applicable", "Could not be computed"):
            assert placeholder not in result, f"{name}: shows {placeholder!r}"


class TestAllThirteenMetrics:
    def test_report_page_has_a_number_for_every_metric(self, app, client, admin, stored, monkeypatch):
        _no_real_decryption(app, monkeypatch)
        from submissions import services as svc
        monkeypatch.setattr(svc, "protection_keys", lambda: pytest.fail("production keys read"))
        encrypted, _, _ = stored
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        html = client.get(f"/admin/security-analysis/submissions/{encrypted.id}").get_data(as_text=True)
        rows = metric_rows(html)
        # title (5) + report text (5) + one PNG evidence file (8)
        assert [r[0] for r in rows] == TEXT_METRICS + TEXT_METRICS + IMAGE_METRICS
        assert_numeric(rows)
        for name, label, _ in rows:
            expected = "Synthetic experiment" if name in SYNTHETIC else "This report"
            assert expected in label, f"{name} should be labelled {expected!r}"
        assert len({r[0] for r in rows}) == 11  # 13 metrics; Entropy/Key sensitivity appear for text and image

    def test_text_experiment_is_sized_to_the_report(self, client, admin, stored):
        encrypted, _, _ = stored
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        html = client.get(f"/admin/security-analysis/submissions/{encrypted.id}").get_data(as_text=True)
        length = len(sa.analyse_stored_text(encrypted.content_sealed)["parsed"].ciphertext)
        assert f"same length as this report text ({length} bytes)" in html
        side = max(64, min(256, math.isqrt(encrypted.evidence[0].size_bytes)))
        assert f"Synthetic {side}×{side} test image, sized to this .png file" in html

    def test_experiments_page_has_a_number_for_every_metric(self, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        rows = metric_rows(client.get("/admin/security-analysis/experiments").get_data(as_text=True))
        assert [r[0] for r in rows] == TEXT_METRICS + IMAGE_METRICS
        assert_numeric(rows)

    def test_small_inputs_still_give_valid_numbers(self):
        r = sa.text_experiments(trials=8, sample_bytes=1)
        assert 40 < r["avalanche"]["production_package_pct"] < 60
        assert r["avalanche"]["fixed_nonce_ciphertext_pct"] == pytest.approx(12.5)  # 1 of 8 bits
        assert r["key_sensitivity"]["decryption_rejected_wrong_enc_key"] == 8
        img = sa.image_experiments(side=64, scrub_formats=("GIF",), key_trials=4)
        assert set(img["quality"]) == {sa.ROUND_TRIP, sa.SCRUB_COMPARISONS["GIF"]}
        assert img["key_sensitivity"]["rejected"] == 4 and 99 < img["key_sensitivity"]["npcr"] < 100
        with pytest.raises(ValueError):
            sa.text_experiments(sample_bytes=0)
        with pytest.raises(ValueError):
            sa.image_experiments(side=4)

    def test_production_avalanche_excludes_only_the_fixed_header(self):
        for n in (1, 60, 2048):
            assert 45 < sa.text_experiments(trials=16, sample_bytes=n)["avalanche"]["production_package_pct"] < 55


class TestJournalistReportPage:
    """Security metrics are admin-only; the journalist report page shows none."""

    def test_journalist_page_has_no_security_metrics(self, client, journalist, stored):
        encrypted, _, _ = stored
        login(client, journalist.username, JOURNALIST_PASSWORD)
        html = client.get(f"/journalist/submissions/{encrypted.id}").get_data(as_text=True)
        for marker in ("Security metrics", "Security check", "bits/byte", "metric-table", "Synthetic experiment"):
            assert marker not in html

    def test_other_roles_cannot_open_the_journalist_report(self, client, admin, stored):
        encrypted, _, _ = stored
        url = f"/journalist/submissions/{encrypted.id}"
        assert "/auth/login" in client.get(url, follow_redirects=False).headers["Location"]
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert client.get(url, follow_redirects=False).status_code == 403


# ---------------------------------------------------------------------------
# 4. Colour visualisation: colour stays colour, grayscale stays grayscale
# ---------------------------------------------------------------------------
class TestColourVisualisation:
    def test_visual_mode_rules(self):
        from PIL import Image
        assert sa.visual_mode(Image.new("L", (4, 4), 90)) == "L"
        assert sa.visual_mode(Image.new("LA", (4, 4))) == "L"
        assert sa.visual_mode(Image.new("RGB", (4, 4), (200, 60, 40))) == "RGB"
        assert sa.visual_mode(Image.new("RGB", (4, 4), (70, 70, 70))) == "L"      # gray content in an RGB file
        assert sa.visual_mode(Image.new("RGB", (4, 4), (200, 60, 40)).convert("P")) == "RGB"
        assert sa.visual_mode(Image.new("RGBA", (4, 4), (0, 0, 255, 128))) == "RGB"

    def test_colour_experiment_keeps_rgb(self):
        import io
        from PIL import Image
        r = sa.image_experiments()
        assert r["mode"] == "RGB" and r["channels"] == 3 and r["bytes"] == 3 * r["pixels"]
        original = Image.open(io.BytesIO(r["plain_png"]))
        cipher = Image.open(io.BytesIO(r["cipher_png"]))
        assert original.mode == "RGB" and cipher.mode == "RGB" and original.size == cipher.size == (128, 128)
        assert original.tobytes() == sa.synthetic_image(128, 128).tobytes()      # colours preserved exactly
        assert original.getpixel((45, 45)) == (200, 60, 40)                     # the red shape is still red
        red, green, blue = (band.tobytes() for band in cipher.split())
        assert red != green != blue                                             # colour noise, not gray
        assert set(r["correlation"]["plain_channels"]) == {"R", "G", "B"}
        assert all(abs(v) < 0.1 for c in r["correlation"]["cipher_channels"].values() for v in c.values())
        assert r["entropy"]["cipher"] > 7.9

    def test_grayscale_experiment_stays_grayscale(self):
        import io
        from PIL import Image
        r = sa.image_experiments(grayscale=True)
        assert r["mode"] == "L" and r["channels"] == 1 and r["bytes"] == r["pixels"]
        for key in ("plain_png", "cipher_png"):
            assert Image.open(io.BytesIO(r[key])).mode == "L"
        assert set(r["correlation"]["plain_channels"]) == {"L"}

    def test_cipher_image_bytes_are_the_ciphertext(self):
        import io
        from PIL import Image
        data = os.urandom(70_000)
        png, side, used = sa.cipher_image_png(data, mode="RGB")
        image = Image.open(io.BytesIO(png))
        assert image.mode == "RGB" and side == 152 and used == 152 * 152 * 3
        assert image.tobytes() == data[:used]
        assert sa.cipher_image_png(os.urandom(100), mode="RGB")[1:] == (5, 75)
        with pytest.raises(ValueError):
            sa.cipher_image_png(data, mode="CMYK")

    def test_uploaded_image_is_drawn_as_colour_noise(self, client, admin, stored):
        """Image evidence: RGB noise built from the stored ciphertext, no decryption."""
        import io
        from PIL import Image
        encrypted, _, _ = stored
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        evidence = encrypted.evidence[0]
        image = Image.open(io.BytesIO(client.get(f"/admin/security-analysis/submissions/{encrypted.id}"
                                                 f"/evidence/{evidence.id}/cipher.png").data))
        assert image.mode == "RGB"
        red, green, blue = (band.tobytes() for band in image.split())
        assert red != green and green != blue                      # real colour, not gray
        ciphertext = sa.parse_package(services.evidence_path(evidence).read_bytes()).ciphertext
        assert image.tobytes() == ciphertext[:image.size[0] ** 2 * 3]
        page = client.get(f"/admin/security-analysis/submissions/{encrypted.id}").get_data(as_text=True)
        assert "3 bytes = 1 colour pixel" in page and "keeps no colour or tint" in page

    def test_grayscale_upload_is_also_colour_noise_without_decryption(self, client, admin, monkeypatch):
        """The picture mode comes from the file type alone; nothing is decrypted."""
        import io
        from PIL import Image
        monkeypatch.setattr(services, "read_evidence_file", lambda *_a: pytest.fail("decrypted"))
        buffer = io.BytesIO()
        Image.linear_gradient("L").save(buffer, format="PNG")
        submission, _ = services.create_submission("gray", "gray photo", ("png", buffer.getvalue()))
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        png = client.get(f"/admin/security-analysis/submissions/{submission.id}"
                         f"/evidence/{submission.evidence[0].id}/cipher.png").data
        assert Image.open(io.BytesIO(png)).mode == "RGB"

    def test_text_evidence_stays_grayscale(self, client, admin):
        import io
        from PIL import Image
        submission, _ = services.create_submission("csv", "a csv file", ("csv", b"a,b,c\n" * 400))
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        png = client.get(f"/admin/security-analysis/submissions/{submission.id}"
                         f"/evidence/{submission.evidence[0].id}/cipher.png").data
        assert Image.open(io.BytesIO(png)).mode == "L"

    def test_experiments_page_shows_colour(self, client, admin):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        page = client.get("/admin/security-analysis/experiments").get_data(as_text=True)
        assert "colour (RGB)" in page and "Original (colour)" in page and "Per channel" in page
