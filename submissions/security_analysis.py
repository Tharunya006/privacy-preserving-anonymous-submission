"""Security analysis for the admin pages.

Two strictly separated kinds of analysis:

* **Real reports -- ciphertext only.**  Stored values are parsed from the
  protected-package format (``submissions.crypto``) without any key and are
  never decrypted.  Pre-Phase-5 records that are still plaintext are detected
  and withheld, never shown.
* **Controlled experiments -- synthetic data, throwaway keys.**  Every metric
  that needs plaintext (avalanche, key sensitivity, NPCR/UACI, MSE/PSNR/SSIM,
  plaintext-vs-ciphertext comparisons) runs on generated sample text and images,
  encrypted with fresh random keys that exist only for that run.  The
  production keys are never used or modified here.  Experiments that hold the
  nonce fixed (to isolate diffusion) call AES-GCM directly with those throwaway
  keys; production encryption always uses a fresh random nonce.

Everything is plain Python plus Pillow and ``cryptography`` (already project
dependencies).  Statistical results describe the ciphertext; they do not prove
the scheme secure -- that rests on AES-256-GCM and HMAC-SHA-256 themselves.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import math
import os
import statistics
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image, ImageDraw

from . import crypto

# Statistics on very large ciphertexts use the first MAX_STAT_BYTES (reported).
MAX_STAT_BYTES = 2 * 1024 * 1024
MAX_CORRELATION_PAIRS = 200_000
CIPHER_IMAGE_SIDE = 256
CHI2_CRITICAL_255_P05 = 293.25  # chi-square, 255 degrees of freedom, p = 0.05

_HEADER_SIZE = crypto._HEADER.size
_PACKAGE_OVERHEAD = _HEADER_SIZE + crypto.NONCE_BYTES + crypto.TAG_BYTES + crypto.MAC_BYTES


# ---------------------------------------------------------------------------
# Generic statistics (pure functions)
# ---------------------------------------------------------------------------
def byte_histogram(data: bytes) -> list[int]:
    counts = Counter(data)
    return [counts.get(i, 0) for i in range(256)]


def shannon_entropy(data: bytes) -> float | None:
    """Bits per byte (0 = constant, 8 = uniformly random bytes); None for no data."""
    if not data:
        return None
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def max_entropy_for_length(n: int) -> float:
    """Highest entropy n bytes can show (a sample shorter than 256 cannot reach 8)."""
    return min(8.0, math.log2(n)) if n > 1 else 0.0


def chi_square_uniform(data: bytes) -> float | None:
    n = len(data)
    if not n:
        return None
    expected = n / 256
    return sum((c - expected) ** 2 / expected for c in byte_histogram(data))


def pearson(xs: list[int] | bytes, ys: list[int] | bytes) -> float | None:
    n = min(len(xs), len(ys))
    if n < 2:
        return None
    xs, ys = xs[:n], ys[:n]
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    syy = sum((y - my) ** 2 for y in ys)
    if sxx == 0 or syy == 0:
        return None  # a constant sequence has no defined correlation
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    return sxy / math.sqrt(sxx * syy)


def adjacent_correlation(data: bytes, step: int = 1) -> float | None:
    """Correlation between each byte and the byte ``step`` positions later."""
    pairs = len(data) - step
    if pairs < 2:
        return None
    stride = max(1, pairs // MAX_CORRELATION_PAIRS)
    xs = data[0:pairs:stride]
    ys = data[step:step + pairs:stride]
    return pearson(xs, ys)


def bit_difference(a: bytes, b: bytes) -> float | None:
    """Percentage of differing bits over the common length (None for no data)."""
    n = min(len(a), len(b))
    if not n:
        return None
    x = int.from_bytes(a[:n], "big") ^ int.from_bytes(b[:n], "big")
    return 100.0 * x.bit_count() / (8 * n)


def npcr_uaci(a: bytes, b: bytes) -> tuple[float | None, float | None]:
    """NPCR and UACI (%) between two equal-length 8-bit images (as bytes)."""
    n = min(len(a), len(b))
    if not n:
        return None, None
    changed = sum(1 for x, y in zip(a[:n], b[:n]) if x != y)
    intensity = sum(abs(x - y) for x, y in zip(a[:n], b[:n]))
    return 100.0 * changed / n, 100.0 * intensity / (255 * n)


def image_correlations(pixels: bytes, width: int, height: int) -> dict[str, float | None]:
    """Adjacent-pixel correlation: horizontal, vertical and diagonal."""
    def pairs(dx, dy):
        xs, ys = [], []
        for y in range(height - dy):
            row, nxt = y * width, (y + dy) * width
            for x in range(width - dx):
                xs.append(pixels[row + x])
                ys.append(pixels[nxt + x + dx])
        return xs, ys

    return {name: pearson(*pairs(dx, dy))
            for name, (dx, dy) in {"horizontal": (1, 0), "vertical": (0, 1),
                                   "diagonal": (1, 1)}.items()}


def mse(a: bytes, b: bytes) -> float | None:
    n = min(len(a), len(b))
    return sum((x - y) ** 2 for x, y in zip(a[:n], b[:n])) / n if n else None


def psnr(mse_value: float | None) -> float | None:
    """dB for 8-bit data; infinite when the images are identical (MSE = 0)."""
    if mse_value is None:
        return None
    return math.inf if mse_value == 0 else 10 * math.log10(255 ** 2 / mse_value)


def ssim(a: bytes, b: bytes, width: int, height: int, window: int = 8, stride: int = 4) -> float | None:
    """Mean SSIM (Wang et al. 2004) over sliding 8x8 windows of 8-bit luminance.
    None when the image is smaller than one window (no valid value)."""
    c1, c2 = (0.01 * 255) ** 2, (0.03 * 255) ** 2
    scores = []
    for top in range(0, height - window + 1, stride):
        for left in range(0, width - window + 1, stride):
            xs = [a[(top + r) * width + left + c] for r in range(window) for c in range(window)]
            ys = [b[(top + r) * width + left + c] for r in range(window) for c in range(window)]
            n = len(xs)
            mx, my = sum(xs) / n, sum(ys) / n
            vx = sum((x - mx) ** 2 for x in xs) / (n - 1)
            vy = sum((y - my) ** 2 for y in ys) / (n - 1)
            cov = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / (n - 1)
            scores.append(((2 * mx * my + c1) * (2 * cov + c2)) /
                          ((mx * mx + my * my + c1) * (vx + vy + c2)))
    return sum(scores) / len(scores) if scores else None


def bucket_histogram(hist: list[int], buckets: int = 64) -> list[int]:
    """Group a 256-bin histogram into fewer bars for display."""
    size = 256 // buckets
    return [sum(hist[i:i + size]) for i in range(0, 256, size)]


def ciphertext_statistics(data: bytes) -> dict:
    """Entropy, frequency (chi-square) and correlation of a byte string."""
    sample = data[:MAX_STAT_BYTES]
    hist = byte_histogram(sample)
    return {
        "bytes_total": len(data),
        "bytes_analysed": len(sample),
        "entropy": shannon_entropy(sample),
        "entropy_max": max_entropy_for_length(len(sample)),
        "chi_square": chi_square_uniform(sample),
        "chi_square_meaningful": len(sample) >= 5 * 256,  # >= 5 expected per bin
        "distinct_byte_values": sum(1 for c in hist if c),
        "serial_correlation": adjacent_correlation(sample),
        "histogram": hist,
        "histogram_bars": bucket_histogram(hist),
    }


# ---------------------------------------------------------------------------
# Real stored data: parse, never decrypt
# ---------------------------------------------------------------------------
@dataclass
class ParsedPackage:
    version: int
    timestamp: datetime
    nonce: bytes
    ciphertext: bytes  # AES-GCM ciphertext without the tag
    tag: bytes
    mac: bytes
    package_size: int


def parse_package(package: bytes) -> ParsedPackage | None:
    """Split a protected package into its public parts.  No key is involved."""
    if len(package) < _PACKAGE_OVERHEAD:
        return None
    magic, version, stamp = crypto._HEADER.unpack_from(package)
    if magic != crypto.MAGIC:
        return None
    nonce_end = _HEADER_SIZE + crypto.NONCE_BYTES
    body_end = len(package) - crypto.MAC_BYTES
    return ParsedPackage(
        version=version,
        timestamp=crypto.from_micros(stamp),
        nonce=package[_HEADER_SIZE:nonce_end],
        ciphertext=package[nonce_end:body_end - crypto.TAG_BYTES],
        tag=package[body_end - crypto.TAG_BYTES:body_end],
        mac=package[body_end:],
        package_size=len(package),
    )


def analyse_stored_text(value: str | None) -> dict:
    """Describe a stored text column.  Plaintext (legacy) values are withheld.

    Only the AES-GCM ciphertext body is offered for display (base64url).  The
    full stored value is never returned: it also contains the GCM tag and the
    HMAC, which are authentication values and are not shown in the UI."""
    if not crypto.is_sealed_text(value):
        return {"state": "legacy"}
    try:
        package = base64.b64decode(value[len(crypto.TEXT_PREFIX):], altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        return {"state": "malformed"}
    parsed = parse_package(package)
    if parsed is None:
        return {"state": "malformed"}
    return {"state": "encrypted", "parsed": parsed,
            "ciphertext_b64": base64.urlsafe_b64encode(parsed.ciphertext).decode("ascii"),
            "stats": ciphertext_statistics(parsed.ciphertext)}


# ---------------------------------------------------------------------------
# Stored representations (actual stored bytes; no key, nothing decrypted)
#
#   envelope = the complete stored protected package, exactly as stored:
#              "P5" | version | timestamp | nonce | ciphertext | GCM tag | HMAC
#              (text: the base64url-decoded column value; evidence: the file)
#   payload  = the AES-GCM ciphertext alone (no header, nonce, tag or HMAC)
#
# A SHA-256 here is a digest of STORED ENCRYPTED BYTES -- never of the original
# report or file -- and it is not proof of authenticity: anyone able to change
# the stored bytes can recompute it.
# ---------------------------------------------------------------------------
ENVELOPE_OVERHEAD = _PACKAGE_OVERHEAD


def stored_text_envelope(value: str | None) -> bytes | None:
    """The envelope bytes of a stored ``p5:`` text value; None for legacy or invalid values."""
    if not crypto.is_sealed_text(value):
        return None
    try:
        return base64.b64decode(value[len(crypto.TEXT_PREFIX):], altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        return None


def representation_metrics(data: bytes, stats: dict | None = None) -> dict:
    """Size and SHA-256 of all the bytes; byte histogram, entropy and chi-square
    of the first MAX_STAT_BYTES (``stats`` may be passed in if already computed)."""
    stats = stats or ciphertext_statistics(data)
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "bytes_analysed": stats["bytes_analysed"], "entropy": stats["entropy"],
            "entropy_max": stats["entropy_max"], "chi_square": stats["chi_square"],
            "distinct_byte_values": stats["distinct_byte_values"], "histogram_bars": stats["histogram_bars"]}


def stored_representations(envelope: bytes, payload_stats: dict | None = None) -> dict | None:
    """Metrics of the envelope and of the payload; None if not a valid package."""
    parsed = parse_package(envelope)
    if parsed is None:
        return None
    return {"envelope": representation_metrics(envelope),
            "payload": representation_metrics(parsed.ciphertext, payload_stats)}


def analyse_stored_file(raw: bytes | None) -> dict:
    """Describe a stored evidence file.  Legacy plaintext files are withheld."""
    if raw is None:
        return {"state": "missing"}
    if not raw.startswith(crypto.MAGIC):
        return {"state": "legacy"}
    parsed = parse_package(raw)
    if parsed is None:
        return {"state": "malformed"}
    return {"state": "encrypted", "parsed": parsed, "stats": ciphertext_statistics(parsed.ciphertext)}


GRAYSCALE_MODES = {"1", "L", "LA", "I", "I;16", "F"}


def visual_mode(image: Image.Image) -> str:
    """'L' for grayscale content, 'RGB' for colour content.

    Grayscale modes stay grayscale.  Colour modes (RGB, RGBA, palette, CMYK...)
    are 'RGB' unless every pixel has equal red, green and blue values."""
    if image.mode in GRAYSCALE_MODES:
        return "L"
    red, green, blue = image.convert("RGB").split()
    return "L" if red.tobytes() == green.tobytes() == blue.tobytes() else "RGB"


def cipher_image_png(ciphertext: bytes, side: int = CIPHER_IMAGE_SIDE, mode: str = "L") -> tuple[bytes, int, int]:
    """Visualise ciphertext bytes as a picture: one byte per pixel ('L') or
    three bytes per pixel ('RGB', colour noise).

    Uses the first ``side * side`` pixels' worth of bytes (or the largest square
    that fits).  Returns (png, side, bytes_used).  The data is only read.
    """
    if mode not in ("L", "RGB"):
        raise ValueError("mode must be 'L' or 'RGB'")
    channels = 3 if mode == "RGB" else 1
    usable = min(side, int(math.isqrt(len(ciphertext) // channels)))
    if usable < 1:
        raise ValueError("ciphertext too short to visualise")
    used = usable * usable * channels
    image = Image.frombytes(mode, (usable, usable), bytes(ciphertext[:used]))
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue(), usable, used


# ---------------------------------------------------------------------------
# Controlled experiments (synthetic data, throwaway keys)
# ---------------------------------------------------------------------------
def _experiment_keys() -> crypto.Keys:
    return crypto.Keys(encryption=os.urandom(crypto.KEY_BYTES), mac=os.urandom(crypto.KEY_BYTES))


def _flip_bit(data: bytes, bit_index: int) -> bytes:
    out = bytearray(data)
    out[bit_index // 8] ^= 1 << (bit_index % 8)
    return bytes(out)


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


_CTX = {"purpose": "analysis.experiment", "binding": "synthetic"}


def _body(package: bytes) -> bytes:
    return parse_package(package).ciphertext


def synthetic_text(length: int = 2048) -> bytes:
    base = ("The quick brown fox jumps over the lazy dog while the auditor reviews "
            "invoice 4471 for the harbour warehouse contract. ")
    return (base * (length // len(base) + 1)).encode("ascii")[:length]


def synthetic_image(width: int = 128, height: int = 128, grayscale: bool = False) -> Image.Image:
    """A deterministic test scene: gradient background plus coloured shapes
    (or the same scene in grayscale, mode 'L')."""
    image = Image.linear_gradient("L").resize((width, height)).convert("RGB")
    draw = ImageDraw.Draw(image)
    w, h = width / 128, height / 128  # shapes are laid out for 128x128 and scaled
    draw.ellipse((20 * w, 20 * h, 70 * w, 70 * h), fill=(200, 60, 40))
    draw.rectangle((70 * w, 60 * h, 115 * w, 110 * h), fill=(40, 120, 200))
    draw.line((0, height - 1, width - 1, 0), fill=(250, 250, 250), width=max(1, round(3 * w)))
    return image.convert("L") if grayscale else image


def _median_ms(fn, runs: int) -> float:
    samples = []
    for _ in range(runs):
        t0 = time.perf_counter_ns()
        fn()
        samples.append((time.perf_counter_ns() - t0) / 1e6)
    return statistics.median(samples)


def text_experiments(trials: int = 32, sample_bytes: int = 2048) -> dict:
    """The five text metrics, measured on ``sample_bytes`` of synthetic text
    (the report page passes the length of a real report's ciphertext)."""
    if sample_bytes < 1:
        raise ValueError("sample_bytes must be at least 1")
    keys = _experiment_keys()
    plaintext = synthetic_text(sample_bytes)
    nonce, aad = os.urandom(crypto.NONCE_BYTES), b"analysis"
    aes = AESGCM(keys.encryption)
    base_fixed = aes.encrypt(nonce, plaintext, aad)
    sealed_at = _now()
    package = crypto.seal(keys, plaintext, timestamp=sealed_at, **_CTX)
    body = _body(package)

    bit_positions = [(i * 1013) % (len(plaintext) * 8) for i in range(trials)]
    ct_diff, tag_diff, pkg_diff = [], [], []
    for bit in bit_positions:
        flipped = _flip_bit(plaintext, bit)
        other = aes.encrypt(nonce, flipped, aad)  # same key, same nonce
        ct_diff.append(bit_difference(base_fixed[:-16], other[:-16]))
        tag_diff.append(bit_difference(base_fixed[-16:], other[-16:]))
        # Compare everything encryption produces (nonce, ciphertext, tag, HMAC); the
        # 11-byte header (format marker, version, timestamp) is fixed by design.
        other = crypto.seal(keys, flipped, timestamp=sealed_at, **_CTX)
        pkg_diff.append(bit_difference(package[_HEADER_SIZE:], other[_HEADER_SIZE:]))

    # Control: the SAME plaintext sealed twice (fresh nonces).  If this is as
    # large as the one-bit result, the difference comes from the random nonce
    # (randomized encryption), not from the plaintext change.
    same_diff = []
    for _ in range(trials):
        again = crypto.seal(keys, plaintext, timestamp=sealed_at, **_CTX)
        same_diff.append(bit_difference(package[_HEADER_SIZE:], again[_HEADER_SIZE:]))

    key_ct, key_mac, rejected_enc, rejected_mac = [], [], 0, 0
    now = _now()
    reference = crypto.seal(keys, plaintext, timestamp=now, **_CTX)
    for i in range(trials):
        bit = (i * 37) % (crypto.KEY_BYTES * 8)
        enc_flipped = crypto.Keys(_flip_bit(keys.encryption, bit), keys.mac)
        mac_flipped = crypto.Keys(keys.encryption, _flip_bit(keys.mac, bit))
        key_ct.append(bit_difference(base_fixed[:-16],
                                     AESGCM(enc_flipped.encryption).encrypt(nonce, plaintext, aad)[:-16]))
        key_mac.append(bit_difference(crypto._mac(keys, _CTX["purpose"], _CTX["binding"], reference[:-32]),
                                      crypto._mac(mac_flipped, _CTX["purpose"], _CTX["binding"], reference[:-32])))
        for wrong, counter in ((enc_flipped, "enc"), (mac_flipped, "mac")):
            try:
                crypto.open_package(wrong, reference, expected_timestamp=now, **_CTX)
            except crypto.IntegrityCheckError:
                if counter == "enc":
                    rejected_enc += 1
                else:
                    rejected_mac += 1

    plain_stats, cipher_stats = ciphertext_statistics(plaintext), ciphertext_statistics(body)
    letters = Counter(chr(b) for b in plaintext if chr(b).isalpha())
    return {
        "sample_bytes": len(plaintext), "trials": trials,
        "entropy": {"plaintext": plain_stats["entropy"], "ciphertext": cipher_stats["entropy"],
                    "max_for_length": cipher_stats["entropy_max"]},
        "avalanche": {
            "fixed_nonce_ciphertext_pct": statistics.fmean(ct_diff),
            "fixed_nonce_tag_pct": statistics.fmean(tag_diff),
            "production_package_pct": statistics.fmean(pkg_diff),
            "fresh_nonce_same_plaintext_pct": statistics.fmean(same_diff),
        },
        "frequency": {
            "plaintext_chi_square": plain_stats["chi_square"],
            "ciphertext_chi_square": cipher_stats["chi_square"],
            "plaintext_distinct": plain_stats["distinct_byte_values"],
            "ciphertext_distinct": cipher_stats["distinct_byte_values"],
            "top_plaintext_letters": letters.most_common(5),
            "plaintext_bars": plain_stats["histogram_bars"],
            "ciphertext_bars": cipher_stats["histogram_bars"],
        },
        "correlation": {
            "plaintext_vs_ciphertext": pearson(plaintext, body),
            "plaintext_serial": plain_stats["serial_correlation"],
            "ciphertext_serial": cipher_stats["serial_correlation"],
        },
        "key_sensitivity": {
            "ciphertext_pct_after_1bit_key_flip": statistics.fmean(key_ct),
            "mac_pct_after_1bit_key_flip": statistics.fmean(key_mac),
            "decryption_rejected_wrong_enc_key": rejected_enc,
            "decryption_rejected_wrong_mac_key": rejected_mac,
        },
    }


# How Phase 3 scrubbing re-saves each image type, for the MSE/PSNR/SSIM pairs.
SCRUB_COMPARISONS = {
    "PNG": "uploaded PNG vs metadata-scrubbed PNG (lossless)",
    "GIF": "uploaded GIF vs metadata-scrubbed GIF (lossless)",
    "JPEG": "uploaded JPEG vs metadata-scrubbed JPEG (re-encoded, quality 95)",
    "WEBP": "uploaded WebP vs metadata-scrubbed WebP (re-encoded, quality 95)",
}
ROUND_TRIP = "original vs decrypted (encrypt/decrypt round trip)"


def _channel_correlations(pixels: bytes, width: int, height: int, channels: int) -> dict:
    """Adjacent-pixel correlation per colour channel (one entry for grayscale)."""
    names = ("R", "G", "B") if channels == 3 else ("L",)
    return {name: image_correlations(pixels[i::channels], width, height) for i, name in enumerate(names)}


def _mean_correlation(per_channel: dict) -> dict:
    """Average of the per-channel H/V/D correlations (None if any is undefined)."""
    out = {}
    for direction in ("horizontal", "vertical", "diagonal"):
        values = [c[direction] for c in per_channel.values()]
        out[direction] = None if any(v is None for v in values) else statistics.fmean(values)
    return out


def image_experiments(side: int = 128, scrub_formats: tuple[str, ...] = ("PNG", "JPEG"),
                      key_trials: int = 8, grayscale: bool = False) -> dict:
    """The eight image metrics, measured on a synthetic ``side`` x ``side``
    image (the report page sizes it to a real evidence file).

    A colour image is encrypted as its RGB pixel bytes (3 per pixel) and shown
    in colour, its cipher-image as colour noise; a grayscale image stays one
    byte per pixel.  Histogram, entropy, NPCR and UACI use every channel value;
    pixel correlation is per channel (and averaged); MSE / PSNR / SSIM compare
    brightness."""
    from .scrubber import scrub_image

    if side < 8:
        raise ValueError("side must be at least 8 pixels (one SSIM window)")
    keys = _experiment_keys()
    image = synthetic_image(side, side, grayscale=grayscale)
    width, height = image.size
    mode = visual_mode(image)
    channels = 3 if mode == "RGB" else 1
    pixels = image.convert(mode).tobytes()
    gray = image.convert("L").tobytes()  # brightness, for MSE / PSNR / SSIM
    now = _now()

    package = crypto.seal(keys, pixels, timestamp=now, **_CTX)
    cipher = _body(package)  # same length as the pixel data -> a cipher-image

    # NPCR / UACI: one pixel changed by one level (its first channel).
    changed_pixel = bytearray(pixels)
    changed_pixel[((height // 2) * width + width // 2) * channels] ^= 0x01
    changed_pixel = bytes(changed_pixel)
    nonce, aad = os.urandom(crypto.NONCE_BYTES), b"analysis"
    aes = AESGCM(keys.encryption)
    fixed_a = aes.encrypt(nonce, pixels, aad)[:-16]
    fixed_b = aes.encrypt(nonce, changed_pixel, aad)[:-16]
    fresh_b = _body(crypto.seal(keys, changed_pixel, timestamp=now, **_CTX))

    # Key sensitivity: same image, encryption key differs by one bit; averaged
    # over ``key_trials`` different key bits.
    key_npcr, key_uaci, key_bits, rejected = [], [], [], 0
    for i in range(key_trials):
        flipped_keys = crypto.Keys(_flip_bit(keys.encryption, (i * 37) % (crypto.KEY_BYTES * 8)), keys.mac)
        other_key = AESGCM(flipped_keys.encryption).encrypt(nonce, pixels, aad)[:-16]
        n_, u_ = npcr_uaci(fixed_a, other_key)
        key_npcr.append(n_), key_uaci.append(u_), key_bits.append(bit_difference(fixed_a, other_key))
        try:
            crypto.open_package(flipped_keys, package, expected_timestamp=now, **_CTX)
        except crypto.IntegrityCheckError:
            rejected += 1

    # MSE / PSNR / SSIM: only comparisons between images of the same content.
    def encode(img, fmt, **kw):
        buffer = io.BytesIO()
        img.save(buffer, format=fmt, **kw)
        return buffer.getvalue()

    def luminance(data: bytes) -> bytes:
        return Image.open(io.BytesIO(data)).convert("L").tobytes()

    original_png = encode(image, "PNG")
    roundtrip = crypto.open_package(keys, crypto.seal(keys, original_png, timestamp=now, **_CTX),
                                    expected_timestamp=now, **_CTX)
    pairs = {ROUND_TRIP: (gray, luminance(roundtrip))}
    uploads = {  # what a source might upload in each format
        "PNG": lambda: original_png,
        "GIF": lambda: encode(image.convert("P", palette=Image.Palette.ADAPTIVE), "GIF"),
        "JPEG": lambda: encode(image, "JPEG", quality=100),
        "WEBP": lambda: encode(image, "WEBP", quality=100),
    }
    for fmt in scrub_formats:
        upload = uploads[fmt]()
        pairs[SCRUB_COMPARISONS[fmt]] = (luminance(upload), luminance(scrub_image(upload)[1]))
    comparisons = {}
    for label, (a, b) in pairs.items():
        m = mse(a, b)
        comparisons[label] = {"mse": m, "psnr": psnr(m), "ssim": ssim(a, b, width, height)}

    plain_stats, cipher_stats = ciphertext_statistics(pixels), ciphertext_statistics(cipher)
    fixed_npcr, fixed_uaci = npcr_uaci(fixed_a, fixed_b)
    fresh_npcr, fresh_uaci = npcr_uaci(cipher, fresh_b)
    # Control: the SAME image encrypted again with a fresh nonce.
    same_npcr, same_uaci = npcr_uaci(cipher, _body(crypto.seal(keys, pixels, timestamp=now, **_CTX)))
    plain_channels = _channel_correlations(pixels, width, height, channels)
    cipher_channels = _channel_correlations(cipher, width, height, channels)
    return {
        "width": width, "height": height, "pixels": width * height, "bytes": len(pixels),
        "mode": mode, "channels": channels,
        "histogram": {"plain_bars": plain_stats["histogram_bars"],
                      "cipher_bars": cipher_stats["histogram_bars"],
                      "plain_chi_square": plain_stats["chi_square"],
                      "cipher_chi_square": cipher_stats["chi_square"]},
        "entropy": {"plain": plain_stats["entropy"], "cipher": cipher_stats["entropy"]},
        "correlation": {"plain": _mean_correlation(plain_channels), "cipher": _mean_correlation(cipher_channels),
                        "plain_channels": plain_channels, "cipher_channels": cipher_channels},
        "npcr_uaci": {"fixed_nonce": (fixed_npcr, fixed_uaci),
                      "production_fresh_nonce": (fresh_npcr, fresh_uaci),
                      "same_image_fresh_nonce": (same_npcr, same_uaci)},
        "key_sensitivity": {"npcr": statistics.fmean(key_npcr), "uaci": statistics.fmean(key_uaci),
                            "bit_difference_pct": statistics.fmean(key_bits),
                            "rejected": rejected, "trials": key_trials,
                            "wrong_key_rejected": rejected == key_trials},
        "quality": comparisons,
        "plain_png": encode(image.convert(mode), "PNG"),
        "cipher_png": cipher_image_png(cipher, side=width, mode=mode)[0],
    }


def performance(sizes: list[tuple[str, int]], runs: int = 5) -> list[dict]:
    """Encryption / decryption time of the production construction on
    size-matched synthetic data (throwaway keys)."""
    keys = _experiment_keys()
    rows = []
    for label, size in sizes:
        data = os.urandom(max(size, 0))
        now = _now()
        package = crypto.seal(keys, data, timestamp=now, **_CTX)
        n = runs if size <= 1_000_000 else max(3, runs // 2)
        enc = _median_ms(lambda: crypto.seal(keys, data, timestamp=now, **_CTX), n)
        dec = _median_ms(lambda: crypto.open_package(keys, package, expected_timestamp=now, **_CTX), n)
        rows.append({
            "label": label, "bytes": size, "runs": n,
            "encrypt_ms": enc, "decrypt_ms": dec,
            "encrypt_mb_s": (size / 1e6) / (enc / 1e3) if enc and size else None,
            "decrypt_mb_s": (size / 1e6) / (dec / 1e3) if dec and size else None,
            "package_bytes": len(package),
        })
    return rows
