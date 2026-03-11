"""Shared test fixtures and helpers."""

from __future__ import annotations

import sqlite3
from pathlib import Path


def init_sqlite_db(path: Path) -> None:
    """Create a test SQLite database with customers, orders, and secrets tables."""
    conn = sqlite3.connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE customers (
              id INTEGER PRIMARY KEY,
              email TEXT NOT NULL,
              ssn TEXT
            );
            CREATE TABLE orders (
              id INTEGER PRIMARY KEY,
              total NUMERIC
            );
            CREATE TABLE secrets (
              id INTEGER PRIMARY KEY,
              token TEXT
            );
            INSERT INTO customers (id, email, ssn) VALUES (1, 'a@example.com', '111-22-3333');
            INSERT INTO orders (id, total) VALUES (10, 19.99);
            """
        )
        conn.commit()
    finally:
        conn.close()


def write_policy(path: Path, content: str) -> None:
    """Write policy file content to path."""
    path.write_text(content, encoding="utf-8")
