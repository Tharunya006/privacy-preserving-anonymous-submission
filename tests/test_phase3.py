"""Phase 3 -- evidence metadata scrubbing.

Proves that EXIF (including GPS), XMP, ICC profiles, comments and PNG text
chunks are removed *before* evidence is stored, that only the cleaned file is
ever written, that bad input is refused safely, and that the Phase 1/2/4 flows
around evidence still work.
"""

from __future__ import annotations

import io
import os
import re
import struct
import zlib
from pathlib import Path

import pytest
from PIL import Image, ImageCms, PngImagePlugin

from phase2.extensions import db
from phase2.models import AuditLog
from submissions import InMemoryUploadRequest, scrubber
from submissions.models import Evidence, Submission
from submissions.scrubber import (
    ScrubError,
    assert_image_is_clean,
    clean_text,
    scrub_evidence,
    scrub_image,
)
from submissions.services import create_submission, evidence_path, read_evidence_file
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME, JOURNALIST_PASSWORD, login

SECRET = "JaneSource-Camera-SN-998877"
GPS_IFD = 0x8825


# ---------------------------------------------------------------------------
# Test images carrying identifying metadata
# ---------------------------------------------------------------------------
def make_exif(orientation: int | None = None) -> Image.Exif:
    exif = Image.Exif()
    exif[0x010F] = "SecretMake"            # Make
    exif[0x0110] = SECRET                  # Model
    exif[0x0131] = "SecretEditor 1.0"      # Software
    exif[0x0132] = "2026:10:01 12:00:00"   # DateTime
    if orientation:
        exif[0x0112] = orientation
    gps = exif.get_ifd(GPS_IFD)
    gps[1], gps[2] = "N", (51.0, 30.0, 12.5)
    gps[3], gps[4] = "W", (0.0, 7.0, 39.0)
    return exif


XMP = (
    '<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF><dc:creator>'
    + SECRET
    + "</dc:creator></rdf:RDF></x:xmpmeta>"
).encode()
ICC = ImageCms.ImageCmsProfile(ImageCms.createProfile("sRGB")).tobytes()


def jpeg_with_metadata(size=(40, 20), orientation=None, mode="RGB") -> bytes:
    buffer = io.BytesIO()
    Image.new(mode, size, (200, 30, 30) if mode == "RGB" else 0).save(
        buffer, format="JPEG", exif=make_exif(orientation), xmp=XMP, icc_profile=ICC,
        comment=SECRET.encode(),
    )
    return buffer.getvalue()


def png_with_metadata(mode="RGBA") -> bytes:
    info = PngImagePlugin.PngInfo()
    info.add_text("Author", SECRET)
    info.add_itxt("XML:com.adobe.xmp", XMP.decode())
    image = Image.new(mode, (40, 20), (1, 2, 3, 128) if mode == "RGBA" else (1, 2, 3))
    buffer = io.BytesIO()
    image.save(buffer, format="PNG", pnginfo=info, exif=make_exif(), icc_profile=ICC)
    return buffer.getvalue()


def webp_with_metadata() -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", (40, 20), (10, 200, 10)).save(
        buffer, format="WEBP", exif=make_exif(), xmp=XMP, icc_profile=ICC
    )
    return buffer.getvalue()


def gif_with_metadata() -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", (40, 20), (10, 10, 200)).save(buffer, format="GIF", comment=SECRET.encode())
    return buffer.getvalue()


SAMPLES = {
    "jpg": jpeg_with_metadata,
    "png": png_with_metadata,
    "webp": webp_with_metadata,
    "gif": gif_with_metadata,
}


def metadata_of(data: bytes) -> dict:
    with Image.open(io.BytesIO(data)) as image:
        exif = image.getexif()
        return {
            "exif": dict(exif),
            "gps": dict(exif.get_ifd(GPS_IFD)),
            "info": {k for k in image.info
                     if k in ("exif", "xmp", "XML:com.adobe.xmp", "icc_profile", "comment")},
            "text": dict(getattr(image, "text", {}) or {}),
        }


def assert_no_identifying_bytes(data: bytes) -> None:
    for marker in (SECRET.encode(), b"SecretMake", b"SecretEditor", b"Exif\x00\x00",
                   b"adobe:ns:meta", b"2026:10:01"):
        assert marker not in data, marker


# ---------------------------------------------------------------------------
# 1. The scrubber itself
# ---------------------------------------------------------------------------
class TestScrubImage:
    @pytest.mark.parametrize("extension", list(SAMPLES))
    def test_metadata_is_removed(self, extension):
        raw = SAMPLES[extension]()
        assert SECRET.encode() in raw  # the sample really does carry metadata

        stored_ext, clean = scrub_evidence(extension, raw)
        assert stored_ext == extension
        assert_no_identifying_bytes(clean)
        meta = metadata_of(clean)
        assert meta == {"exif": {}, "gps": {}, "info": set(), "text": {}}
        assert_image_is_clean(clean)
        with Image.open(io.BytesIO(clean)) as image:
            image.load()  # still a valid, decodable image
            assert image.size == (40, 20)

    @pytest.mark.parametrize("extension", ["jpg", "png", "webp"])
    def test_gps_position_is_removed(self, extension):
        raw = SAMPLES[extension]()
        assert metadata_of(raw)["gps"], "sample should contain GPS"
        _, clean = scrub_evidence(extension, raw)
        assert metadata_of(clean)["gps"] == {}

    def test_orientation_is_applied_before_exif_is_dropped(self):
        raw = jpeg_with_metadata(size=(40, 20), orientation=6)  # "rotate 90 CW"
        _, clean = scrub_image(raw)
        with Image.open(io.BytesIO(clean)) as image:
            assert image.size == (20, 40)
            assert 0x0112 not in image.getexif()

    def test_lossless_pixels_are_preserved(self):
        raw = png_with_metadata()
        _, clean = scrub_image(raw)
        with Image.open(io.BytesIO(raw)) as before, Image.open(io.BytesIO(clean)) as after:
            assert before.mode == after.mode
            assert before.tobytes() == after.tobytes()

    def test_palette_and_transparency_are_preserved(self):
        image = Image.new("P", (16, 16))
        image.putpalette([(i * 7) % 256 for i in range(768)])
        image.putdata(range(256))
        info = PngImagePlugin.PngInfo()
        info.add_text("Author", SECRET)
        buffer = io.BytesIO()
        image.save(buffer, format="PNG", transparency=5, pnginfo=info)

        _, clean = scrub_image(buffer.getvalue())
        assert SECRET.encode() not in clean
        with Image.open(io.BytesIO(buffer.getvalue())) as a, Image.open(io.BytesIO(clean)) as b:
            assert a.convert("RGBA").tobytes() == b.convert("RGBA").tobytes()

    def test_cmyk_jpeg_is_supported(self):
        _, clean = scrub_image(jpeg_with_metadata(mode="CMYK"))
        assert_no_identifying_bytes(clean)
        assert Image.open(io.BytesIO(clean)).mode == "CMYK"

    def test_animated_gif_keeps_the_first_frame(self):
        frames = [Image.new("P", (10, 10), i) for i in (1, 2, 3)]
        buffer = io.BytesIO()
        frames[0].save(buffer, format="GIF", save_all=True, append_images=frames[1:],
                       comment=SECRET.encode())
        _, clean = scrub_image(buffer.getvalue())
        assert SECRET.encode() not in clean
        assert getattr(Image.open(io.BytesIO(clean)), "n_frames", 1) == 1

    def test_real_format_decides_the_stored_extension(self):
        stored_ext, clean = scrub_evidence("png", jpeg_with_metadata())
        assert stored_ext == "jpg"
        assert Image.open(io.BytesIO(clean)).format == "JPEG"

    @pytest.mark.parametrize(
        "data",
        [
            b"",
            b"definitely not an image",
            b"\x89PNG\r\n\x1a\n" + b"\x00" * 64,           # PNG signature, garbage body
            jpeg_with_metadata()[:200],                      # truncated JPEG
            b"GIF89a" + os.urandom(64),
            b"%PDF-1.7\n" + b"x" * 100,                      # PDF renamed to .jpg
        ],
    )
    def test_corrupted_or_fake_images_are_refused(self, data):
        with pytest.raises(ScrubError, match="could not be read"):
            scrub_evidence("jpg", data)

    def test_formats_outside_the_allow_list_are_refused(self):
        buffer = io.BytesIO()
        Image.new("RGB", (4, 4)).save(buffer, format="BMP")
        with pytest.raises(ScrubError):
            scrub_evidence("jpg", buffer.getvalue())

    def test_decompression_bomb_header_is_refused_before_decoding(self):
        # A ~60-byte PNG that declares a 100000 x 100000 canvas.
        def chunk(kind, payload):
            return (struct.pack(">I", len(payload)) + kind + payload
                    + struct.pack(">I", zlib.crc32(kind + payload)))
        bomb = (b"\x89PNG\r\n\x1a\n"
                + chunk(b"IHDR", struct.pack(">IIBBBBB", 100_000, 100_000, 8, 2, 0, 0, 0))
                + chunk(b"IDAT", zlib.compress(b"\x00" * 10))
                + chunk(b"IEND", b""))
        with pytest.raises(ScrubError, match="too large"):
            scrub_evidence("png", bomb)

    def test_pixel_limit_is_enforced(self, monkeypatch):
        monkeypatch.setattr(scrubber, "MAX_IMAGE_PIXELS", 100)
        with pytest.raises(ScrubError, match="too large"):
            scrub_evidence("png", png_with_metadata())

    def test_dirty_image_fails_the_final_check(self):
        with pytest.raises(ScrubError, match="could not be removed"):
            assert_image_is_clean(jpeg_with_metadata())


class TestOtherTypes:
    def test_utf8_text_is_kept(self):
        assert scrub_evidence("txt", "Café report\n".encode()) == ("txt", "Café report\n".encode())

    def test_byte_order_mark_is_dropped(self):
        assert clean_text(b"\xef\xbb\xbfa,b\n") == b"a,b\n"

    @pytest.mark.parametrize("data", [b"\xff\xfe\x00b\x00a", b"abc\x00def", jpeg_with_metadata()])
    def test_binary_renamed_to_text_is_refused(self, data):
        with pytest.raises(ScrubError, match="UTF-8"):
            scrub_evidence("txt", data)

    @pytest.mark.parametrize("extension", ["pdf", "docx", "xlsx", "odt", "exe", "svg", "heic", ""])
    def test_types_that_cannot_be_cleaned_are_refused(self, extension):
        with pytest.raises(ScrubError, match="cannot be cleaned"):
            scrub_evidence(extension, b"anything")


# ---------------------------------------------------------------------------
# 2. Scrubbing happens before storage, and only the clean file is kept
# ---------------------------------------------------------------------------
def submit(client, evidence, title="Report with photo"):
    return client.post(
        "/submit",
        data={"title": title, "content": "See attached.", "evidence": evidence},
        content_type="multipart/form-data",
    )


def stored_files(app) -> list[Path]:
    directory = Path(app.config["EVIDENCE_DIR"])
    return sorted(directory.iterdir()) if directory.exists() else []


class TestSubmissionPipeline:
    @pytest.mark.parametrize("extension", list(SAMPLES))
    def test_only_the_clean_image_is_stored(self, app, client, extension):
        raw = SAMPLES[extension]()
        response = submit(client, (io.BytesIO(raw), f"IMG_by_Jane_Doe.{extension}"))
        assert response.status_code == 200

        files = stored_files(app)
        assert len(files) == 1, files  # no temp / original copy left behind
        on_disk = files[0].read_bytes()
        assert on_disk.startswith(b"P5")  # Phase 5: stored encrypted
        evidence = db.session.query(Evidence).one()
        data = read_evidence_file(evidence)  # verified + decrypted
        assert data != raw
        assert_no_identifying_bytes(data)
        assert metadata_of(data)["gps"] == {}
        assert evidence.size_bytes == len(data)
        assert evidence.stored_name == files[0].name
        assert "jane" not in evidence.stored_name.lower()
        assert "jane" not in evidence.download_name.lower()

    def test_service_scrubs_even_when_called_directly(self, app):
        submission, _ = create_submission("direct", "body", ("jpg", jpeg_with_metadata()))
        data = read_evidence_file(submission.evidence[0])
        assert_no_identifying_bytes(data)
        assert metadata_of(data)["gps"] == {}

    @pytest.mark.parametrize(
        "upload,message",
        [
            ((io.BytesIO(b"not an image"), "photo.jpg"), b"could not be read"),
            ((io.BytesIO(jpeg_with_metadata()[:150]), "cut.jpg"), b"could not be read"),
            ((io.BytesIO(b"%PDF-1.7 author=Jane"), "leak.pdf"), b"not accepted"),
            ((io.BytesIO(b"PK\x03\x04 docx"), "leak.docx"), b"not accepted"),
        ],
    )
    def test_rejected_evidence_stores_nothing(self, app, client, upload, message):
        response = submit(client, upload)
        assert response.status_code == 400
        assert message in response.data
        assert stored_files(app) == []
        assert db.session.query(Submission).count() == 0
        assert db.session.query(AuditLog).count() == 0

    def test_uploads_never_spool_to_a_temporary_file(self, app, client, monkeypatch):
        """The unscrubbed upload stays in memory, even above Werkzeug's 500 KB
        spool threshold, so the original never reaches the disk."""
        import tempfile

        import werkzeug.formparser

        def forbidden(*args, **kwargs):
            raise AssertionError("upload was spooled to disk")

        monkeypatch.setattr(werkzeug.formparser, "SpooledTemporaryFile", forbidden)
        monkeypatch.setattr(werkzeug.formparser, "TemporaryFile", forbidden, raising=False)
        monkeypatch.setattr(tempfile, "TemporaryFile", forbidden)

        assert app.request_class is InMemoryUploadRequest
        noise = Image.frombytes("RGB", (500, 500), os.urandom(500 * 500 * 3))
        buffer = io.BytesIO()
        noise.save(buffer, format="PNG", exif=make_exif())
        assert len(buffer.getvalue()) > 600 * 1024

        response = submit(client, (io.BytesIO(buffer.getvalue()), "big.png"))
        assert response.status_code == 200
        assert_no_identifying_bytes(read_evidence_file(db.session.query(Evidence).one()))

    def test_receipt_and_status_still_work(self, client):
        response = submit(client, (io.BytesIO(jpeg_with_metadata()), "p.jpg"))
        token = re.search(rb"<code>([A-Za-z0-9_-]{32})</code>", response.data).group(1)
        assert len(token) == 32  # the existing 192-bit token, not Phase 3's SUB-xxxx
        status = client.post("/status", data={"token": token.decode()})
        assert status.status_code == 200 and b"Submitted" in status.data

    def test_source_page_explains_scrubbing(self, client):
        page = client.get("/submit").data
        assert b"removed automatically before the" in page
        assert b'accept=".jpg,.jpeg,.png,.gif,.webp,.txt,.csv"' in page


# ---------------------------------------------------------------------------
# 3. Phase 2 + Phase 4 around scrubbed evidence
# ---------------------------------------------------------------------------
class TestJournalistAccessToCleanEvidence:
    def test_journalist_downloads_the_clean_image(self, app, client, journalist):
        submit(client, (io.BytesIO(jpeg_with_metadata()), "gps.jpg"))
        evidence = db.session.query(Evidence).one()
        login(client, journalist.username, JOURNALIST_PASSWORD)

        url = f"/journalist/submissions/{evidence.submission_id}/evidence/{evidence.id}"
        response = client.get(url)
        assert response.status_code == 200
        assert response.data == read_evidence_file(evidence)
        assert response.data != stored_files(app)[0].read_bytes()  # disk holds ciphertext
        assert response.headers["Content-Disposition"].startswith("attachment")
        assert_no_identifying_bytes(response.data)
        assert metadata_of(response.data)["gps"] == {}

        page = client.get(f"/journalist/submissions/{evidence.submission_id}").data
        assert b"metadata" in page and b"removed before storage" in page

    def test_access_control_is_unchanged(self, app, client, admin):
        submit(client, (io.BytesIO(png_with_metadata()), "x.png"))
        evidence = db.session.query(Evidence).one()
        url = f"/journalist/submissions/{evidence.submission_id}/evidence/{evidence.id}"
        assert client.get(url, follow_redirects=False).status_code == 302
        login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert client.get(url).status_code == 403

    def test_workflow_and_audit_with_scrubbed_evidence(self, app, client, journalist):
        submit(client, (io.BytesIO(webp_with_metadata()), "Jane_Doe_GPS.webp"))
        sub = db.session.query(Submission).one()
        login(client, journalist.username, JOURNALIST_PASSWORD)
        client.get(f"/journalist/submissions/{sub.id}/evidence/{sub.evidence[0].id}")
        client.post(f"/journalist/submissions/{sub.id}/status", data={"status": "UNDER_REVIEW"})
        db.session.expire_all()
        assert db.session.get(Submission, sub.id).status == "UNDER_REVIEW"

        for entry in db.session.query(AuditLog):
            text = " ".join(str(v) for v in (entry.target, entry.detail) if v)
            assert "Jane" not in text and SECRET not in text
            assert sub.evidence[0].stored_name not in text


# ---------------------------------------------------------------------------
# 4. Cleaning evidence stored before Phase 3
# ---------------------------------------------------------------------------
class TestScrubEvidenceCommand:
    def _legacy(self, app, extension: str, data: bytes) -> Evidence:
        """Store a file the way the pre-Phase-3 code did: as uploaded."""
        submission, _ = create_submission("legacy", "body")
        directory = Path(app.config["EVIDENCE_DIR"])
        directory.mkdir(parents=True, exist_ok=True)
        name = f"{os.urandom(16).hex()}.{extension}"
        (directory / name).write_bytes(data)
        evidence = Evidence(submission_id=submission.id, stored_name=name,
                            extension=extension, size_bytes=len(data))
        db.session.add(evidence)
        db.session.commit()
        return evidence

    def test_cleans_legacy_images_and_reports_documents(self, app):
        dirty = self._legacy(app, "jpg", jpeg_with_metadata())
        pdf = self._legacy(app, "pdf", b"%PDF-1.7 /Author (Jane)")
        old_path = evidence_path(dirty)
        runner = app.test_cli_runner()

        dry = runner.invoke(args=["scrub-evidence", "--dry-run"])
        assert dry.exit_code == 0, dry.output
        assert "would be cleaned" in dry.output
        assert old_path.read_bytes() == jpeg_with_metadata()

        result = runner.invoke(args=["scrub-evidence"])
        assert result.exit_code == 0, result.output
        assert ".pdf cannot be cleaned" in result.output
        db.session.expire_all()
        cleaned = db.session.get(Evidence, dirty.id)
        assert not old_path.exists()  # the original is deleted
        data = read_evidence_file(cleaned)
        assert_no_identifying_bytes(data)
        assert metadata_of(data)["gps"] == {}
        assert cleaned.size_bytes == len(data)
        assert evidence_path(cleaned).read_bytes().startswith(b"P5")  # now encrypted too
        assert evidence_path(db.session.get(Evidence, pdf.id)).exists()  # never auto-deleted
        assert db.session.query(AuditLog).filter_by(action="evidence.scrubbed").count() == 1

    def test_is_idempotent(self, app):
        self._legacy(app, "jpg", jpeg_with_metadata())
        runner = app.test_cli_runner()
        runner.invoke(args=["scrub-evidence"])
        before = [p.read_bytes() for p in stored_files(app)]
        result = runner.invoke(args=["scrub-evidence"])
        assert "0 cleaned, 1 already clean" in result.output
        assert [p.read_bytes() for p in stored_files(app)] == before
