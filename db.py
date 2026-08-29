import sqlite3
from pathlib import Path

from flask import current_app, g


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")

    return g.db


def close_db(_error=None):
    database = g.pop("db", None)
    if database is not None:
        database.close()


def init_db():
    schema_path = Path(__file__).with_name("schema.sql")
    database = get_db()
    database.executescript(schema_path.read_text(encoding="utf-8"))
    database.commit()


def init_app(app):
    app.teardown_appcontext(close_db)
