"""Database path resolution for Phase 2.

Regression cover for the "unable to open database file" bootstrap failure:
a relative SQLite path used to be resolved by Flask-SQLAlchemy against
``instance_path``, producing ``instance/instance/phase2.db`` in a directory
that nobody had created.
"""

from __future__ import annotations

from pathlib import Path

from phase2 import create_app
from phase2.config import (
    BASE_DIR,
    DEFAULT_DATABASE_URI,
    INSTANCE_DIR,
    ensure_database_directory,
    normalise_database_uri,
    sqlite_file_path,
)


class TestNormaliseDatabaseUri:
    def test_relative_path_is_anchored_to_the_project_root(self):
        uri = normalise_database_uri("sqlite:///instance/phase2.db")
        assert uri == f"sqlite:///{(INSTANCE_DIR / 'phase2.db').as_posix()}"

    def test_relative_path_does_not_nest_under_instance_twice(self):
        uri = normalise_database_uri("sqlite:///instance/phase2.db")
        assert "instance/instance" not in uri

    def test_relative_path_is_independent_of_the_working_directory(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        assert normalise_database_uri("sqlite:///instance/phase2.db") == DEFAULT_DATABASE_URI

    def test_absolute_path_is_left_alone(self, tmp_path):
        uri = f"sqlite:///{(tmp_path / 'phase2.db').as_posix()}"
        assert normalise_database_uri(uri) == uri

    def test_path_containing_spaces_survives(self):
        root = Path("/tmp/IS project/repo")
        uri = normalise_database_uri("sqlite:///instance/phase2.db", root=root)
        assert uri == "sqlite:////tmp/IS project/repo/instance/phase2.db"

    def test_in_memory_uris_are_untouched(self):
        assert normalise_database_uri("sqlite://") == "sqlite://"
        assert normalise_database_uri("sqlite:///:memory:") == "sqlite:///:memory:"

    def test_other_backends_are_untouched(self):
        uri = "postgresql+psycopg://user@localhost/phase2"
        assert normalise_database_uri(uri) == uri

    def test_is_idempotent(self):
        once = normalise_database_uri("sqlite:///instance/phase2.db")
        assert normalise_database_uri(once) == once


class TestSqliteFilePath:
    def test_returns_the_file_for_a_real_path(self):
        assert sqlite_file_path(DEFAULT_DATABASE_URI) == INSTANCE_DIR / "phase2.db"

    def test_returns_none_for_in_memory(self):
        assert sqlite_file_path("sqlite://") is None
        assert sqlite_file_path("sqlite:///:memory:") is None

    def test_returns_none_for_other_backends(self):
        assert sqlite_file_path("postgresql://localhost/phase2") is None

    def test_query_string_is_not_part_of_the_path(self, tmp_path):
        db = (tmp_path / "phase2.db").as_posix()
        assert sqlite_file_path(f"sqlite:///{db}?timeout=30") == Path(db)


class TestEnsureDatabaseDirectory:
    def test_creates_missing_parents(self, tmp_path):
        target = tmp_path / "deeply" / "nested" / "phase2.db"
        ensure_database_directory(f"sqlite:///{target.as_posix()}")
        assert target.parent.is_dir()

    def test_is_a_no_op_for_in_memory(self):
        ensure_database_directory("sqlite://")


class TestDefaults:
    def test_default_uri_points_into_the_project_instance_dir(self):
        assert sqlite_file_path(DEFAULT_DATABASE_URI) == BASE_DIR / "instance" / "phase2.db"


class TestCreateApp:
    def test_creates_the_database_directory_up_front(self, tmp_path):
        target = tmp_path / "somewhere" / "phase2.db"
        create_app(
            "testing",
            SQLALCHEMY_DATABASE_URI=f"sqlite:///{target.as_posix()}",
        )
        assert target.parent.is_dir()

    def test_normalises_a_relative_override(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        app = create_app("testing", SQLALCHEMY_DATABASE_URI="sqlite:///instance/phase2.db")
        assert app.config["SQLALCHEMY_DATABASE_URI"] == DEFAULT_DATABASE_URI

    def test_testing_config_stays_in_memory(self):
        app = create_app("testing")
        assert app.config["SQLALCHEMY_DATABASE_URI"] == "sqlite://"

    def test_engine_opens_against_the_configured_file(self, tmp_path):
        target = tmp_path / "fresh" / "phase2.db"
        app = create_app(
            "testing",
            SQLALCHEMY_DATABASE_URI=f"sqlite:///{target.as_posix()}",
        )
        from phase2.extensions import db

        with app.app_context():
            db.create_all()
        assert target.is_file()
