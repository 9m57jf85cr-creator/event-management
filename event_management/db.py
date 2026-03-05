import sqlite3

from .legacy_migrations import (
    ensure_bookings_contact_fields,
    ensure_bookings_created_at,
    ensure_bookings_email_status_fields,
    ensure_bookings_reference_code,
    ensure_events_capacity,
    generate_booking_reference,
    migrate_bookings_table,
)
from .schema import (
    create_bookings_table,
    create_events_table,
    ensure_booking_audit_table,
    ensure_request_rate_limit_table,
    log_booking_audit,
    update_booking_confirmation_email_status as _update_booking_confirmation_email_status,
)


def get_db_connection(app):
    """Create a SQLite connection with foreign key enforcement enabled."""
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def update_booking_confirmation_email_status(app, booking_id, status, error_message):
    """Persist the current confirmation-email delivery status for a booking."""
    _update_booking_confirmation_email_status(
        get_db_connection,
        app,
        booking_id,
        status,
        error_message,
    )


def init_db(app):
    """Initialize core tables and apply legacy compatibility migrations."""
    conn = get_db_connection(app)
    cursor = conn.cursor()

    create_events_table(cursor)
    create_bookings_table(cursor)

    migrate_bookings_table(cursor)
    ensure_bookings_created_at(cursor)
    ensure_bookings_reference_code(cursor)
    ensure_bookings_contact_fields(cursor)
    ensure_bookings_email_status_fields(cursor)
    ensure_events_capacity(cursor)
    ensure_booking_audit_table(cursor)
    ensure_request_rate_limit_table(cursor)
    conn.commit()
    conn.close()


__all__ = [
    "get_db_connection",
    "generate_booking_reference",
    "log_booking_audit",
    "update_booking_confirmation_email_status",
    "init_db",
]
