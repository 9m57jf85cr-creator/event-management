from pathlib import Path


def _migrations_dir():
    return Path(__file__).resolve().parent.parent / "migrations" / "versions"


def _ensure_migrations_table(cursor):
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )


def list_migrations():
    return sorted(path.name for path in _migrations_dir().glob("*.sql"))


def apply_pending_migrations(app, get_db_connection):
    conn = get_db_connection(app)
    cursor = conn.cursor()
    _ensure_migrations_table(cursor)
    cursor.execute("SELECT version FROM schema_migrations")
    applied = {row[0] for row in cursor.fetchall()}

    for version in list_migrations():
        if version in applied:
            continue

        sql_path = _migrations_dir() / version
        script = sql_path.read_text(encoding="utf-8")
        cursor.executescript(script)
        cursor.execute("INSERT INTO schema_migrations (version) VALUES (?)", (version,))

    conn.commit()
    conn.close()
