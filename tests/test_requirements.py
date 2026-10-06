"""Guard the dependency file against encoding regressions.

Phase 1's requirements.txt was saved as UTF-16.  Without a byte-order mark pip
decodes such a file as UTF-8, every line after the first starts with a NUL
byte, comments stop being recognised as comments, and installation fails with
``InvalidMarker`` on the first comment that contains a ``;``.
"""

from __future__ import annotations

import re
from pathlib import Path

REQUIREMENTS = Path(__file__).resolve().parent.parent / "requirements.txt"

# name, optional extras, then version specifiers -- no markers, URLs or options.
REQUIREMENT_LINE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9,._-]+\])?"
    r"((==|>=|<=|~=|!=|<|>)[A-Za-z0-9.*+!-]+)(,(==|>=|<=|~=|!=|<|>)[A-Za-z0-9.*+!-]+)*$"
)


def test_requirements_is_plain_utf8():
    raw = REQUIREMENTS.read_bytes()
    assert not raw.startswith((b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")), "unexpected BOM"
    assert b"\x00" not in raw, "NUL bytes: the file is UTF-16, not UTF-8"
    assert b"\r" not in raw, "use LF line endings"
    raw.decode("utf-8")


def test_every_line_is_a_comment_or_a_pinned_requirement():
    for lineno, line in enumerate(REQUIREMENTS.read_text("utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        assert REQUIREMENT_LINE.match(stripped), f"line {lineno} is not a plain requirement: {line!r}"


def test_phase2_dependencies_are_present():
    names = {
        re.split(r"[<>=!~\[]", line.strip(), maxsplit=1)[0].lower()
        for line in REQUIREMENTS.read_text("utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert {"flask", "werkzeug", "flask-sqlalchemy", "flask-wtf", "python-dotenv"} <= names
