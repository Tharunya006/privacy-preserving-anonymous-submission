"""Security metrics are admin-only.

The journalist report page shows the report, its evidence and the status
workflow -- and no security metrics, no analysis calculations and no extra
evidence decryption.  The admin analysis pages keep every metric.
"""

from __future__ import annotations

import base64
import io

import pytest
from PIL import Image

from phase2.extensions import db
from submissions import security_analysis as sa
from submissions import services
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, JOURNALIST_PASSWORD, login

TITLE = "Harbour payments QUOKKA-TITLE"
BODY = "Payments were made in cash every Friday. ZEBRA-BODY"


def small_png() -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", (16, 16), (20, 140, 110)).save(buffer, format="PNG")
    return buffer.getvalue()


@pytest.fixture()
def report(app):
    submission, _ = services.create_submission(TITLE, BODY, ("png", small_png()))
    return submission


def detail(submission):
    return f"/journalist/submissions/{submission.id}"


class TestJournalistPageHasNoMetrics:
    def test_report_page_shows_report_but_no_metrics(self, client, journalist, report):
        login(client, journalist.username, JOURNALIST_PASSWORD)
        response = client.get(detail(report))
        html = response.get_data(as_text=True)
        assert response.status_code == 200
        assert TITLE in html and BODY in html          # authorized access unchanged
        assert "Download" in html                      # evidence still offered
        for marker in ("Security metrics", "Security check", "bits/byte", "Actual report data",
                       "Synthetic experiment", "Wrong-key check", "metric-table"):
            assert marker not in html, marker

    def test_no_analysis_code_runs_for_the_journalist_page(self, client, journalist, report, monkeypatch):
        """No metric calculation and no extra evidence decryption on page view."""
        def forbidden(*_args, **_kwargs):
            pytest.fail("security analysis ran on the journalist page")

        for name in ("text_experiments", "image_experiments", "ciphertext_statistics",
                     "analyse_stored_text", "analyse_stored_file", "performance"):
            monkeypatch.setattr(sa, name, forbidden)
        import phase2.blueprints.journalist as views
        monkeypatch.setattr(views, "read_evidence_file", lambda *_a: pytest.fail("evidence decrypted on page view"))
        login(client, journalist.username, JOURNALIST_PASSWORD)
        assert client.get(detail(report)).status_code == 200

    def test_download_and_integrity_checks_still_work(self, client, journalist, report):
        login(client, journalist.username, JOURNALIST_PASSWORD)
        evidence = report.evidence[0]
        download = client.get(f"{detail(report)}/evidence/{evidence.id}")
        assert download.status_code == 200 and download.data.startswith(b"\x89PNG")
        package = bytearray(base64.urlsafe_b64decode(report.content_sealed[3:]))
        package[30] ^= 0x01
        report.content_sealed = "p5:" + base64.urlsafe_b64encode(bytes(package)).decode()
        db.session.commit()
        assert client.get(detail(report)).status_code == 409

    def test_removed_journalist_helpers_are_gone(self):
        for name in ("text_metrics", "image_statistics", "wrong_key_check", "byte_statistics",
                     "stored_text_package", "MIN_RELIABLE_BYTES"):
            assert not hasattr(sa, name), name


class TestAdminKeepsTheMetrics:
    def test_admin_report_and_experiments_still_show_metrics(self, client, admin, report):
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        page = client.get(f"/admin/security-analysis/submissions/{report.id}").get_data(as_text=True)
        assert "Text metrics (5)" in page and "Image metrics (8)" in page
        assert "This report" in page and "Synthetic experiment" in page
        assert TITLE not in page and BODY not in page   # admin still ciphertext-only
        experiments = client.get("/admin/security-analysis/experiments").get_data(as_text=True)
        assert "Text metrics (5)" in experiments and "Image metrics (8)" in experiments

    def test_journalist_still_cannot_open_admin_analysis(self, client, journalist, report):
        login(client, journalist.username, JOURNALIST_PASSWORD)
        for url in ("/admin/security-analysis", f"/admin/security-analysis/submissions/{report.id}",
                    "/admin/security-analysis/experiments", "/admin/security-analysis/hashing"):
            assert client.get(url, follow_redirects=False).status_code == 403
