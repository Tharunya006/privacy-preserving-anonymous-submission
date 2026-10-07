"""Evidence metadata scrubbing (Phase 3).

Every evidence file passes through ``scrub_evidence`` **in memory, before
anything is written to disk**; only its output is ever stored.  The original
upload is never saved, not even to a temporary file (see ``InMemoryUploadRequest``
for the request side of that guarantee).

Images (JPEG, PNG, GIF, WebP)
    The image is decoded and its pixels are copied into a brand-new image object
    that has no metadata at all, which is then re-encoded.  This drops EXIF
    (including GPS position, camera make/model/serial and timestamps), XMP, IPTC,
    ICC profiles, JPEG comments and PNG text chunks -- whatever the source format
    carried, because nothing but pixels is copied.  The EXIF orientation is
    applied to the pixels first so the cleaned image still displays upright.
    The output is decoded again and checked; if any metadata survived, the file
    is rejected rather than stored.

Plain text (TXT, CSV)
    Has no embedded metadata.  It must be valid UTF-8 without NUL bytes, so a
    binary file (or an image) renamed to ``.txt`` is refused; a UTF-8 byte-order
    mark is dropped.

Anything that cannot be cleaned is rejected with ``ScrubError``.  Documents such
as PDF or Word files are not accepted at all, because their author/software
metadata cannot be removed with Pillow.
"""

from __future__ import annotations

import io
import warnings

from PIL import Image, ImageOps, UnidentifiedImageError

# extension -> Pillow format name
IMAGE_FORMATS = {
    "jpg": "JPEG",
    "jpeg": "JPEG",
    "png": "PNG",
    "gif": "GIF",
    "webp": "WEBP",
}
# Pillow format name -> extension used for the stored, cleaned file
FORMAT_EXTENSIONS = {"JPEG": "jpg", "PNG": "png", "GIF": "gif", "WEBP": "webp"}
TEXT_EXTENSIONS = frozenset({"txt", "csv"})
SCRUBBABLE_EXTENSIONS = frozenset(IMAGE_FORMATS) | TEXT_EXTENSIONS

# Decompression-bomb guard: a small file can declare an enormous canvas.
MAX_IMAGE_PIXELS = 40_000_000

# Keys under which Pillow exposes embedded metadata after decoding.
_METADATA_INFO_KEYS = (
    "exif", "xmp", "XML:com.adobe.xmp", "icc_profile", "comment", "photoshop",
    "iptc", "adobe_transform_data",
)

_UNREADABLE = "The image could not be read. It may be corrupted or not a real image."
_TOO_LARGE = "The image dimensions are too large to process."


class ScrubError(ValueError):
    """Evidence that cannot be cleaned.  The message is safe to show the source."""


def scrub_evidence(extension: str, data: bytes) -> tuple[str, bytes]:
    """Return ``(extension, cleaned_bytes)`` for an uploaded evidence file.

    For images the returned extension reflects the real format of the content,
    so a JPEG uploaded as ``photo.png`` is stored as a ``.jpg``.
    """
    extension = (extension or "").lower()
    if extension in IMAGE_FORMATS:
        return scrub_image(data)
    if extension in TEXT_EXTENSIONS:
        return extension, clean_text(data)
    raise ScrubError("That file type cannot be cleaned of metadata and is not accepted.")


# ---------------------------------------------------------------------------
# Images
# ---------------------------------------------------------------------------
def scrub_image(data: bytes) -> tuple[str, bytes]:
    try:
        with warnings.catch_warnings():
            # Pillow only *warns* between MAX_IMAGE_PIXELS and twice that; treat
            # the warning as an error so oversized canvases are always refused.
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            fmt = _identify(data)
            with Image.open(io.BytesIO(data), formats=[fmt]) as original:
                _check_dimensions(original)
                original.seek(0)  # animated GIF/WebP: the first frame only
                original.load()
                upright = ImageOps.exif_transpose(original)
                clean = _pixels_only(upright, fmt)
            output = _encode(clean, fmt)
    except ScrubError:
        raise
    except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
        raise ScrubError(_TOO_LARGE) from exc
    except (UnidentifiedImageError, OSError, SyntaxError, ValueError,
            EOFError, MemoryError) as exc:
        raise ScrubError(_UNREADABLE) from exc

    assert_image_is_clean(output)
    return FORMAT_EXTENSIONS[fmt], output


def _identify(data: bytes) -> str:
    """Detect the real format from the content, and check the file is intact."""
    with Image.open(io.BytesIO(data), formats=list(FORMAT_EXTENSIONS)) as probe:
        fmt = probe.format
        _check_dimensions(probe)
        probe.verify()  # structural integrity check; the object is unusable after
    if fmt not in FORMAT_EXTENSIONS:
        raise ScrubError("Only JPEG, PNG, GIF and WebP images are accepted.")
    return fmt


def _check_dimensions(image: Image.Image) -> None:
    width, height = image.size
    if width < 1 or height < 1 or width * height > MAX_IMAGE_PIXELS:
        raise ScrubError(_TOO_LARGE)


def _pixels_only(image: Image.Image, fmt: str) -> Image.Image:
    """A new image built from raw pixel data: ``info`` is empty, so no metadata."""
    image = _compatible_mode(image, fmt)
    clean = Image.frombytes(image.mode, image.size, image.tobytes())
    if image.mode == "P":
        clean.putpalette(image.getpalette())
        # A palette transparency index is rendering data, not metadata.
        transparency = image.info.get("transparency")
        if isinstance(transparency, (int, bytes)):
            clean.info["transparency"] = transparency
    return clean


def _compatible_mode(image: Image.Image, fmt: str) -> Image.Image:
    has_alpha = image.mode in ("RGBA", "LA", "PA") or "transparency" in image.info
    if fmt == "JPEG" and image.mode not in ("L", "RGB", "CMYK"):
        return image.convert("RGB")
    if fmt == "WEBP" and image.mode not in ("RGB", "RGBA"):
        return image.convert("RGBA" if has_alpha else "RGB")
    if fmt == "PNG" and image.mode not in ("1", "L", "LA", "P", "RGB", "RGBA", "I", "I;16"):
        return image.convert("RGBA" if has_alpha else "RGB")
    if fmt == "GIF" and image.mode not in ("1", "L", "P"):
        return image.convert("RGBA" if has_alpha else "RGB").convert(
            "P", palette=Image.Palette.ADAPTIVE
        )
    if image.mode == "PA":
        return image.convert("RGBA")
    return image


def _encode(image: Image.Image, fmt: str) -> bytes:
    buffer = io.BytesIO()
    params: dict = {}
    if fmt == "JPEG":
        params = {"quality": 95}
    elif fmt == "WEBP":
        params = {"quality": 95}
    elif fmt in ("PNG", "GIF") and "transparency" in image.info:
        params = {"transparency": image.info["transparency"]}
    image.save(buffer, format=fmt, **params)
    return buffer.getvalue()


def assert_image_is_clean(data: bytes) -> None:
    """Decode the stored bytes again and refuse them if any metadata remains."""
    try:
        with Image.open(io.BytesIO(data)) as check:
            leftover = [key for key in _METADATA_INFO_KEYS if check.info.get(key)]
            if len(check.getexif()):
                leftover.append("EXIF")
            if getattr(check, "text", None):  # PNG tEXt / iTXt / zTXt chunks
                leftover.append("text chunks")
            if hasattr(check, "applist"):    # JPEG APPn segments
                # Allowed: APP0 (JFIF header) and APP14 "Adobe" (colour-transform
                # flags Pillow itself writes for CMYK) -- neither identifies anyone.
                leftover += [
                    marker for marker, payload in check.applist
                    if marker != "APP0" and not (marker == "APP14" and payload.startswith(b"Adobe"))
                ]
    except ScrubError:
        raise
    except Exception as exc:  # pragma: no cover - our own output must decode
        raise ScrubError(_UNREADABLE) from exc
    if leftover:
        raise ScrubError("The image metadata could not be removed, so it was not stored.")


# ---------------------------------------------------------------------------
# Plain text
# ---------------------------------------------------------------------------
def clean_text(data: bytes) -> bytes:
    if b"\x00" in data:
        raise ScrubError("Text evidence must be plain UTF-8 text.")
    try:
        text = data.decode("utf-8-sig")  # also drops a byte-order mark
    except UnicodeDecodeError as exc:
        raise ScrubError("Text evidence must be plain UTF-8 text.") from exc
    return text.encode("utf-8")
