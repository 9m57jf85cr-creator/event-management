import secrets
import string

from .constants import BOOKING_REFERENCE_LENGTH, MAX_TICKETS


def migrate_bookings_table(cursor):
    cursor.execute("PRAGMA foreign_key_list(bookings)")
    has_fk = bool(cursor.fetchall())
    if has_fk:
        return

    cursor.execute(
        """
        CREATE TABLE bookings_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            user_name TEXT NOT NULL,
            user_email TEXT NOT NULL DEFAULT '',
            user_phone TEXT NOT NULL DEFAULT '',
            confirmation_email_status TEXT NOT NULL DEFAULT 'skipped',
            confirmation_email_error TEXT NOT NULL DEFAULT '',
            tickets INTEGER NOT NULL,
            FOREIGN KEY (event_id) REFERENCES events (id) ON DELETE CASCADE
        )
        """
    )
    cursor.execute(
        """
        INSERT INTO bookings_new (
            id,
            event_id,
            user_name,
            user_email,
            user_phone,
            confirmation_email_status,
            confirmation_email_error,
            tickets
        )
        SELECT b.id, b.event_id, b.user_name, '', '', 'skipped', '', b.tickets
        FROM bookings b
        JOIN events e ON e.id = b.event_id
        """
    )
    cursor.execute("DROP TABLE bookings")
    cursor.execute("ALTER TABLE bookings_new RENAME TO bookings")


def ensure_bookings_created_at(cursor):
    cursor.execute("PRAGMA table_info(bookings)")
    columns = {row[1] for row in cursor.fetchall()}
    if "created_at" not in columns:
        cursor.execute(
            "ALTER TABLE bookings ADD COLUMN created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        )


def generate_booking_reference(cursor):
    alphabet = string.ascii_uppercase + string.digits
    while True:
        reference_code = "".join(secrets.choice(alphabet) for _ in range(BOOKING_REFERENCE_LENGTH))
        cursor.execute("SELECT 1 FROM bookings WHERE reference_code = ?", (reference_code,))
        if cursor.fetchone() is None:
            return reference_code


def ensure_bookings_reference_code(cursor):
    cursor.execute("PRAGMA table_info(bookings)")
    columns = {row[1] for row in cursor.fetchall()}
    if "reference_code" not in columns:
        cursor.execute("ALTER TABLE bookings ADD COLUMN reference_code TEXT")

    cursor.execute("SELECT id FROM bookings WHERE reference_code IS NULL OR reference_code = ''")
    missing_rows = cursor.fetchall()
    for row in missing_rows:
        reference_code = generate_booking_reference(cursor)
        cursor.execute(
            "UPDATE bookings SET reference_code = ? WHERE id = ?",
            (reference_code, row[0]),
        )

    cursor.execute("PRAGMA index_list(bookings)")
    indexes = {row[1] for row in cursor.fetchall()}
    if "idx_bookings_reference_code" not in indexes:
        cursor.execute("CREATE UNIQUE INDEX idx_bookings_reference_code ON bookings(reference_code)")


def ensure_events_capacity(cursor):
    cursor.execute("PRAGMA table_info(events)")
    columns = {row[1] for row in cursor.fetchall()}
    if "capacity" not in columns:
        cursor.execute(
            f"ALTER TABLE events ADD COLUMN capacity INTEGER NOT NULL DEFAULT {MAX_TICKETS}"
        )
    cursor.execute(f"UPDATE events SET capacity = {MAX_TICKETS} WHERE capacity IS NULL OR capacity <= 0")


def ensure_bookings_contact_fields(cursor):
    cursor.execute("PRAGMA table_info(bookings)")
    columns = {row[1] for row in cursor.fetchall()}
    if "user_email" not in columns:
        cursor.execute("ALTER TABLE bookings ADD COLUMN user_email TEXT NOT NULL DEFAULT ''")
    if "user_phone" not in columns:
        cursor.execute("ALTER TABLE bookings ADD COLUMN user_phone TEXT NOT NULL DEFAULT ''")


def ensure_bookings_email_status_fields(cursor):
    cursor.execute("PRAGMA table_info(bookings)")
    columns = {row[1] for row in cursor.fetchall()}
    if "confirmation_email_status" not in columns:
        cursor.execute(
            "ALTER TABLE bookings ADD COLUMN confirmation_email_status TEXT NOT NULL DEFAULT 'skipped'"
        )
    if "confirmation_email_error" not in columns:
        cursor.execute(
            "ALTER TABLE bookings ADD COLUMN confirmation_email_error TEXT NOT NULL DEFAULT ''"
        )
