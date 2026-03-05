"""DDL and schema-level helpers used by database initialization/migrations."""

def create_events_table(cursor):
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            date TEXT NOT NULL,
            location TEXT NOT NULL,
            capacity INTEGER NOT NULL DEFAULT 100
        )
        """
    )


def create_bookings_table(cursor):
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            user_name TEXT NOT NULL,
            user_email TEXT NOT NULL DEFAULT '',
            user_phone TEXT NOT NULL DEFAULT '',
            confirmation_email_status TEXT NOT NULL DEFAULT 'skipped',
            confirmation_email_error TEXT NOT NULL DEFAULT '',
            tickets INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            reference_code TEXT UNIQUE,
            FOREIGN KEY (event_id) REFERENCES events (id) ON DELETE CASCADE
        )
        """
    )


def ensure_booking_audit_table(cursor):
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS booking_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            booking_id INTEGER NOT NULL,
            reference_code TEXT NOT NULL,
            action TEXT NOT NULL,
            actor TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )


def ensure_request_rate_limit_table(cursor):
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS request_rate_limit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scope TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            bucket_start INTEGER NOT NULL,
            request_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(scope, client_ip, bucket_start)
        )
        """
    )


def log_booking_audit(cursor, booking_id, reference_code, action, actor):
    cursor.execute(
        """
        INSERT INTO booking_audit (booking_id, reference_code, action, actor)
        VALUES (?, ?, ?, ?)
        """,
        (booking_id, reference_code, action, actor),
    )


def update_booking_confirmation_email_status(get_db_connection, app, booking_id, status, error_message):
    """Update email status metadata for an existing booking row."""
    conn = get_db_connection(app)
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE bookings
        SET confirmation_email_status = ?, confirmation_email_error = ?
        WHERE id = ?
        """,
        (status, error_message, booking_id),
    )
    conn.commit()
    conn.close()
