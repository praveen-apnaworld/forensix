"""
db.py - Database Connection Helper

This module handles connecting to our SQLite database.
Think of it as the bridge between our Python code and the database file.

Key concepts for beginners:
- get_db(): Gets a database connection (opens the bridge)
- close_db(): Closes the connection when we're done
- init_db(): Creates all the tables from schema.sql (first-time setup)
"""

import os
import sqlite3
from flask import g, current_app


def get_db():
    """
    Get a database connection.

    Flask uses a special object called 'g' to store data during a single request.
    We store the database connection in 'g' so we don't open multiple connections
    for the same request.

    Returns:
        sqlite3.Connection: A connection to the SQLite database
    """
    if 'db' not in g:
        # Connect to the database file specified in our config
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        # This makes rows behave like dictionaries (access columns by name)
        g.db.row_factory = sqlite3.Row
        # Enable foreign key support (ensures data relationships are enforced)
        g.db.execute('PRAGMA foreign_keys = ON')
        check_or_migrate_reports_table(g.db)

    return g.db


def check_or_migrate_reports_table(db):
    """Ensures reports table has all required columns for Step 7."""
    try:
        cols = [r[1] for r in db.execute("PRAGMA table_info(reports)").fetchall()]
        if cols:
            if 'report_id' not in cols:
                db.execute("ALTER TABLE reports ADD COLUMN report_id TEXT")
            if 'report_title' not in cols:
                db.execute("ALTER TABLE reports ADD COLUMN report_title TEXT")
            if 'file_path' not in cols:
                db.execute("ALTER TABLE reports ADD COLUMN file_path TEXT")
            if 'file_size' not in cols:
                db.execute("ALTER TABLE reports ADD COLUMN file_size INTEGER")
            if 'evidence_count' not in cols:
                db.execute("ALTER TABLE reports ADD COLUMN evidence_count INTEGER DEFAULT 0")
            if 'selected_evidence_ids' not in cols:
                db.execute("ALTER TABLE reports ADD COLUMN selected_evidence_ids TEXT")
            db.commit()
    except Exception:
        pass


def close_db(e=None):
    """
    Close the database connection.

    This is called automatically at the end of each request by Flask.
    """
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    """
    Initialize the database by running schema.sql.

    This creates all the tables if they don't already exist.
    Safe to call multiple times — it won't destroy existing data.
    """
    db = get_db()

    # Read and execute the schema.sql file
    schema_path = os.path.join(
        os.path.dirname(__file__), 'schema.sql'
    )
    with open(schema_path, 'r') as f:
        db.executescript(f.read())

    db.commit()


def init_app(app):
    """
    Register database functions with the Flask app.

    This tells Flask to:
    1. Close the database connection after each request
    2. Provides a CLI command to initialize the database

    Args:
        app: The Flask application instance
    """
    # Tell Flask to call close_db when cleaning up after a request
    app.teardown_appcontext(close_db)
