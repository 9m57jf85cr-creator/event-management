import os
import sqlite3
import tempfile
import unittest
from contextlib import closing

from app import app, init_db, reset_rate_limit_state
from event_management.repositories.bookings_repo import (
    fetch_admin_bookings_page,
    fetch_audit_rows,
    fetch_booking_for_admin_cancel,
    fetch_booking_for_resend,
    fetch_booking_for_self_cancel,
    fetch_bookings_for_csv,
    fetch_my_bookings_by_reference,
)
from event_management.repositories.events_repo import (
    create_event,
    delete_event,
    fetch_capacity_totals_for_update,
    fetch_event_for_edit,
    fetch_event_with_totals,
    fetch_paginated_events,
    update_event,
)


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)

        app.config["TESTING"] = True
        app.config["DATABASE"] = self.db_path
        app.config["SECRET_KEY"] = "test-secret"
        app.config["ADMIN_USERNAME"] = "admin"
        app.config["ADMIN_PASSWORD"] = "admin123"
        app.config["API_KEY"] = "test-api-key"
        app.config["RATE_LIMIT_WINDOW_SECONDS"] = 60
        app.config["RATE_LIMIT_LOGIN_MAX_REQUESTS"] = 10
        app.config["RATE_LIMIT_BOOKING_MAX_REQUESTS"] = 30
        app.config["SMTP_ENABLED"] = False
        app.config["SMTP_HOST"] = "smtp.test.local"
        app.config["SMTP_PORT"] = 2525
        app.config["SMTP_USERNAME"] = ""
        app.config["SMTP_PASSWORD"] = ""
        app.config["SMTP_USE_TLS"] = True
        app.config["SMTP_FROM_EMAIL"] = "no-reply@test.local"
        reset_rate_limit_state()
        init_db()

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def _insert_booking(
        self,
        event_id,
        user_name,
        user_email,
        user_phone,
        status,
        tickets,
        reference_code,
    ):
        with closing(sqlite3.connect(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO bookings (
                    event_id,
                    user_name,
                    user_email,
                    user_phone,
                    confirmation_email_status,
                    confirmation_email_error,
                    tickets,
                    reference_code
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    user_name,
                    user_email,
                    user_phone,
                    status,
                    "",
                    tickets,
                    reference_code,
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def test_events_repo_crud_and_totals(self):
        create_event(app, "Repo Event", "2026-09-01", "Austin", 10)
        with closing(sqlite3.connect(self.db_path)) as conn:
            event_id = conn.execute("SELECT id FROM events WHERE name = ?", ("Repo Event",)).fetchone()[0]

        event = fetch_event_for_edit(app, event_id)
        self.assertEqual(event["location"], "Austin")

        update_event(app, event_id, "Repo Event Updated", "2026-09-02", "Dallas", 20)
        updated = fetch_event_for_edit(app, event_id)
        self.assertEqual(updated["name"], "Repo Event Updated")
        self.assertEqual(updated["capacity"], 20)

        self._insert_booking(
            event_id,
            "Alex",
            "alex@example.com",
            "+1 555 100 0000",
            "pending",
            3,
            "REPOTOTAL1",
        )
        event_with_totals = fetch_event_with_totals(app, event_id)
        self.assertEqual(event_with_totals[4], 20)
        self.assertEqual(event_with_totals[5], 3)

        self.assertTrue(delete_event(app, event_id))
        self.assertFalse(delete_event(app, event_id))

    def test_fetch_paginated_events_with_filters(self):
        create_event(app, "A Event", "2026-01-01", "Austin", 5)
        create_event(app, "B Event", "2026-02-01", "Boston", 5)

        filters = {"where_clause": "WHERE e.location = ?", "params": ["Austin"]}
        rows, page, total_items, total_pages = fetch_paginated_events(app, filters, page=1, per_page=10)

        self.assertEqual(page, 1)
        self.assertEqual(total_items, 1)
        self.assertEqual(total_pages, 1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1], "A Event")

    def test_fetch_capacity_totals_for_update(self):
        create_event(app, "Capacity Event", "2026-03-01", "Austin", 4)
        with closing(sqlite3.connect(self.db_path)) as conn:
            event_id = conn.execute("SELECT id FROM events WHERE name = ?", ("Capacity Event",)).fetchone()[0]
        self._insert_booking(
            event_id,
            "User",
            "user@example.com",
            "+1 555 200 0000",
            "pending",
            2,
            "CAPACITY01",
        )

        with closing(sqlite3.connect(self.db_path)) as conn:
            cursor = conn.cursor()
            row = fetch_capacity_totals_for_update(cursor, event_id)

        self.assertEqual(row[0], 4)
        self.assertEqual(row[1], 2)

    def test_bookings_repo_lookup_and_cancel_queries(self):
        create_event(app, "Lookup Event", "2026-04-01", "Austin", 10)
        with closing(sqlite3.connect(self.db_path)) as conn:
            event_id = conn.execute("SELECT id FROM events WHERE name = ?", ("Lookup Event",)).fetchone()[0]

        booking_id = self._insert_booking(
            event_id,
            "Taylor",
            "taylor@example.com",
            "+1 555 300 0000",
            "pending",
            2,
            "LOOKUP0001",
        )

        rows = fetch_my_bookings_by_reference(app, "LOOKUP0001")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][2], "Taylor")

        with closing(sqlite3.connect(self.db_path)) as conn:
            cursor = conn.cursor()
            self_cancel = fetch_booking_for_self_cancel(cursor, "LOOKUP0001")
            admin_cancel = fetch_booking_for_admin_cancel(cursor, booking_id)

        self.assertEqual(self_cancel[1], "LOOKUP0001")
        self.assertEqual(admin_cancel[0], booking_id)

    def test_bookings_repo_admin_page_and_csv_filters(self):
        create_event(app, "Filter Event", "2026-05-01", "Austin", 10)
        with closing(sqlite3.connect(self.db_path)) as conn:
            event_id = conn.execute("SELECT id FROM events WHERE name = ?", ("Filter Event",)).fetchone()[0]

        self._insert_booking(
            event_id,
            "Alice",
            "alice@example.com",
            "+1 555 400 0000",
            "sent",
            1,
            "FILTER0001",
        )
        self._insert_booking(
            event_id,
            "Bob",
            "bob@example.com",
            "+1 555 500 0000",
            "failed",
            2,
            "FILTER0002",
        )

        rows, page, total_pages = fetch_admin_bookings_page(
            app,
            query="Alice",
            status_filter="sent",
            order_by_sql="b.created_at DESC, b.id DESC",
            page=1,
            per_page=10,
        )
        self.assertEqual(page, 1)
        self.assertEqual(total_pages, 1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][2], "Alice")

        csv_rows = fetch_bookings_for_csv(
            app,
            query="",
            status_filter="failed",
            order_by_sql="b.created_at DESC, b.id DESC",
        )
        self.assertEqual(len(csv_rows), 1)
        self.assertEqual(csv_rows[0][2], "Bob")

    def test_bookings_repo_resend_and_audit_queries(self):
        create_event(app, "Audit Event", "2026-06-01", "Austin", 10)
        with closing(sqlite3.connect(self.db_path)) as conn:
            event_id = conn.execute("SELECT id FROM events WHERE name = ?", ("Audit Event",)).fetchone()[0]

        booking_id = self._insert_booking(
            event_id,
            "Sam",
            "sam@example.com",
            "+1 555 600 0000",
            "pending",
            1,
            "AUDIT00001",
        )

        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute(
                "INSERT INTO booking_audit (booking_id, reference_code, action, actor) VALUES (?, ?, ?, ?)",
                (booking_id, "AUDIT00001", "create", "self_service"),
            )
            conn.commit()

        resend_row = fetch_booking_for_resend(app, booking_id)
        self.assertEqual(resend_row[0], booking_id)
        self.assertEqual(resend_row[1], "Sam")

        filters = {"where_clause": "WHERE action = ?", "params": ["create"]}
        rows_with_id = fetch_audit_rows(app, filters, include_id=True)
        rows_without_id = fetch_audit_rows(app, filters, include_id=False)

        self.assertEqual(len(rows_with_id), 1)
        self.assertEqual(len(rows_without_id), 1)
        self.assertEqual(len(rows_with_id[0]), 6)
        self.assertEqual(len(rows_without_id[0]), 5)


if __name__ == "__main__":
    unittest.main()
