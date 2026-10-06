"""Phase 2 configuration.

Kept deliberately separate from any Phase 1 ``config.py`` so the two phases can
be developed in parallel.  Every secret is read from the environment; nothing
sensitive is hard-coded here.
"""

from __future__ import annotations

import os
import secrets
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

# Project root = the directory that contains the `phase2` package.
BASE_DIR = Path(__file__).resolve().parent.parent
INSTANCE_DIR = BASE_DIR / "instance"

# Load a .env file if one is present.  Never fails when the file is absent.
load_dotenv(BASE_DIR / ".env")


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


_SQLITE_FILE_PREFIX = "sqlite:///"

# Default location of the Phase 2 database, as an absolute project-root path.
DEFAULT_DATABASE_URI = f"{_SQLITE_FILE_PREFIX}{(INSTANCE_DIR / 'phase2.db').as_posix()}"


def sqlite_file_path(uri: str) -> Path | None:
    """The file a SQLite URI points at, or ``None`` for in-memory / other backends."""
    if not uri.startswith(_SQLITE_FILE_PREFIX):
        return None                              # "sqlite://" (memory), postgres, ...
    target = uri[len(_SQLITE_FILE_PREFIX):].split("?", 1)[0]
    if not target or target.startswith((":", "file:")):
        return None                              # ":memory:", SQLite URI filenames
    return Path(target)


def normalise_database_uri(uri: str, root: Path = BASE_DIR) -> str:
    """Anchor a relative SQLite path to the project root.

    Flask-SQLAlchemy resolves a relative SQLite path against ``instance_path``,
    which would turn ``sqlite:///instance/phase2.db`` into ``instance/instance/
    phase2.db``.  Anchoring to the project root here keeps the database where
    the path says it is, whatever directory the ``flask`` command is run from.

    The join is normalised lexically (``os.path.abspath``) rather than with
    ``Path.resolve()``: resolving would follow symlinks and rewrite the path the
    caller gave -- on macOS ``/tmp`` silently became ``/private/tmp``.
    """
    path = sqlite_file_path(uri)
    if path is None:
        return uri
    if path.is_absolute():
        return uri
    anchored = Path(os.path.abspath(root / path))
    return f"{_SQLITE_FILE_PREFIX}{anchored.as_posix()}"


def resolve_project_path(raw: str, root: Path = BASE_DIR) -> Path:
    """Anchor a relative filesystem path to the project root."""
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = root / path
    return Path(os.path.abspath(path))


def ensure_database_directory(uri: str) -> None:
    """Create the database file's parent directory before SQLAlchemy opens it."""
    path = sqlite_file_path(uri)
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)


class BaseConfig:
    """Settings shared by every environment."""

    # --- Secrets -----------------------------------------------------------
    # Resolved in ``create_app`` so that a missing key can be reported loudly
    # in production but tolerated (ephemeral key) in development.
    SECRET_KEY: str | None = os.environ.get("PHASE2_SECRET_KEY")

    # --- Database ----------------------------------------------------------
    # A relative SQLite path in PHASE2_DATABASE_URI is resolved against the
    # project root, so the database lands in the same place from any cwd.
    SQLALCHEMY_DATABASE_URI = normalise_database_uri(
        os.environ.get("PHASE2_DATABASE_URI") or DEFAULT_DATABASE_URI
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- Session security --------------------------------------------------
    SESSION_COOKIE_NAME = "phase2_session"
    SESSION_COOKIE_HTTPONLY = True          # JavaScript cannot read the cookie
    SESSION_COOKIE_SAMESITE = "Lax"         # Blocks cross-site form CSRF vectors
    SESSION_COOKIE_SECURE = _env_bool("PHASE2_COOKIE_SECURE", False)
    PERMANENT_SESSION_LIFETIME = timedelta(
        minutes=_env_int("PHASE2_SESSION_MINUTES", 30)
    )
    # Idle timeout enforced in application code (see phase2.security).
    PHASE2_IDLE_TIMEOUT_MINUTES = _env_int("PHASE2_IDLE_TIMEOUT_MINUTES", 15)

    # --- CSRF --------------------------------------------------------------
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = _env_int("PHASE2_CSRF_TIME_LIMIT", 3600)

    # --- Password policy ---------------------------------------------------
    # PBKDF2-HMAC-SHA256 with a high iteration count (OWASP guidance).
    PASSWORD_HASH_METHOD = os.environ.get(
        "PHASE2_HASH_METHOD", "pbkdf2:sha256:600000"
    )
    PASSWORD_MIN_LENGTH = _env_int("PHASE2_PASSWORD_MIN_LENGTH", 10)

    # --- Brute-force protection -------------------------------------------
    MAX_FAILED_LOGINS = _env_int("PHASE2_MAX_FAILED_LOGINS", 5)
    LOCKOUT_MINUTES = _env_int("PHASE2_LOCKOUT_MINUTES", 15)

    # --- Anonymous submissions / evidence ---------------------------------
    # Evidence files live outside every static folder, under instance/ (which
    # is git-ignored), and are only ever served to authorized journalists.
    EVIDENCE_DIR = str(
        resolve_project_path(
            os.environ.get("PHASE2_EVIDENCE_DIR") or str(INSTANCE_DIR / "evidence")
        )
    )
    EVIDENCE_MAX_BYTES = _env_int("PHASE2_EVIDENCE_MAX_MB", 10) * 1024 * 1024
    # Whole-request ceiling: the evidence limit plus room for the text fields.
    # Anything larger is refused with 413 before the body is read.
    MAX_CONTENT_LENGTH = EVIDENCE_MAX_BYTES + 1024 * 1024

    TESTING = False
    DEBUG = False


class DevelopmentConfig(BaseConfig):
    DEBUG = True


class TestingConfig(BaseConfig):
    TESTING = True
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = "sqlite://"    # in-memory, nothing written to disk
    WTF_CSRF_ENABLED = False                 # forms are posted directly in tests
    SECRET_KEY = "testing-only-not-a-real-secret"
    # Fast hashing keeps the suite quick; production keeps the strong default.
    PASSWORD_HASH_METHOD = "pbkdf2:sha256:1000"
    PHASE2_IDLE_TIMEOUT_MINUTES = 15


class ProductionConfig(BaseConfig):
    SESSION_COOKIE_SECURE = _env_bool("PHASE2_COOKIE_SECURE", True)


CONFIG_MAP = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}


def resolve_config(name: str | None = None):
    """Pick a config class by name, falling back to ``PHASE2_ENV``."""
    key = (name or os.environ.get("PHASE2_ENV") or "development").strip().lower()
    return CONFIG_MAP.get(key, DevelopmentConfig)


def generate_dev_secret() -> str:
    """Ephemeral key used only when no PHASE2_SECRET_KEY is configured."""
    return secrets.token_urlsafe(48)
