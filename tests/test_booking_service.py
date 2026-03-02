import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from unittest.mock import patch

from app import app, init_db, reset_rate_limit_state
from event_management.services.booking_service import (
    cancel_booking_admin,
    cancel_booking_self_service,
    create_booking,
    resend_confirmation_email,
)


class BookingServiceTests(unittest.TestCase):
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

    def _create_event(self, name="Service Event", capacity=10):
        with closing(sqlite3.connect(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO events (name, date, location, capacity) VALUES (?, ?, ?, ?)",
                (name, "2026-12-01", "Austin", capacity),
            )
            conn.commit()
            return cursor.lastrowid

    def _insert_booking(self, event_id, user_name="User", tickets=1, reference_code="ABCDEFGHIJ"):
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
                    "user@example.com",
                    "+1 555 000 1111",
                    "pending",
                    "",
                    tickets,
                    reference_code,
                ),
            )
            conn.commit()
            return cursor.lastrowid

    @patch("event_management.services.booking_service.send_booking_confirmation_email")
    def test_create_booking_success(self, mock_send_confirmation):
        mock_send_confirmation.return_value = ("sent", "")
        event_id = self._create_event(capacity=5)

        result = create_booking(
            app=app,
            event_id=event_id,
            name="Alex",
            email="alex@example.com",
            phone="+1 555 123 0000",
            tickets=2,
            event_details={"name": "Service Event", "date": "2026-12-01", "location": "Austin"},
        )

        self.assertEqual(result["status"], "success")
        self.assertEqual(len(result["reference_code"]), 10)

        with closing(sqlite3.connect(self.db_path)) as conn:
            booking = conn.execute(
                "SELECT user_name, tickets, confirmation_email_status FROM bookings WHERE reference_code = ?",
                (result["reference_code"],),
            ).fetchone()
            audit = conn.execute(
                "SELECT action, actor FROM booking_audit ORDER BY id DESC LIMIT 1"
            ).fetchone()

        self.assertEqual(booking[0], "Alex")
        self.assertEqual(booking[1], 2)
        self.assertEqual(booking[2], "sent")
        self.assertEqual(audit, ("create", "self_service"))

    def test_create_booking_event_not_found(self):
        result = create_booking(
            app=app,
            event_id=9999,
            name="Alex",
            email="alex@example.com",
            phone="+1 555 123 0000",
            tickets=1,
            event_details={"name": "Missing", "date": "2026-12-01", "location": "Austin"},
        )
        self.assertEqual(result, {"status": "event_not_found"})

    def test_create_booking_sold_out(self):
        event_id = self._create_event(capacity=1)
        self._insert_booking(event_id, user_name="First", tickets=1, reference_code="AAAAABBBBB")

        result = create_booking(
            app=app,
            event_id=event_id,
            name="Alex",
            email="alex@example.com",
            phone="+1 555 123 0000",
            tickets=1,
            event_details={"name": "Service Event", "date": "2026-12-01", "location": "Austin"},
        )
        self.assertEqual(result, {"status": "sold_out"})

    def test_create_booking_insufficient_tickets(self):
        event_id = self._create_event(capacity=3)
        self._insert_booking(event_id, user_name="First", tickets=2, reference_code="CCCCCDDDDD")

        result = create_booking(
            app=app,
            event_id=event_id,
            name="Alex",
            email="alex@example.com",
            phone="+1 555 123 0000",
            tickets=2,
            event_details={"name": "Service Event", "date": "2026-12-01", "location": "Austin"},
        )
        self.assertEqual(result["status"], "insufficient_tickets")
        self.assertEqual(result["remaining_tickets"], 1)

    @patch("event_management.services.booking_service.send_booking_cancellation_email")
    def test_cancel_booking_self_service_success(self, mock_send_cancel):
        event_id = self._create_event(capacity=3)
        self._insert_booking(event_id, user_name="Alex", tickets=1, reference_code="SELFCANCEL1")

        result = cancel_booking_self_service(app, "SELFCANCEL1")
        self.assertEqual(result, {"status": "success"})

        with closing(sqlite3.connect(self.db_path)) as conn:
            remaining = conn.execute(
                "SELECT COUNT(*) FROM bookings WHERE reference_code = ?",
                ("SELFCANCEL1",),
            ).fetchone()[0]
            audit = conn.execute(
                "SELECT action, actor FROM booking_audit ORDER BY id DESC LIMIT 1"
            ).fetchone()

        self.assertEqual(remaining, 0)
        self.assertEqual(audit, ("cancel", "self_service"))
        mock_send_cancel.assert_called_once()

    @patch("event_management.services.booking_service.send_booking_cancellation_email")
    def test_cancel_booking_admin_success(self, mock_send_cancel):
        event_id = self._create_event(capacity=3)
        booking_id = self._insert_booking(event_id, user_name="Alex", tickets=1, reference_code="ADMINCAN01")

        result = cancel_booking_admin(app, booking_id)
        self.assertEqual(result, {"status": "success"})

        with closing(sqlite3.connect(self.db_path)) as conn:
            remaining = conn.execute(
                "SELECT COUNT(*) FROM bookings WHERE id = ?",
                (booking_id,),
            ).fetchone()[0]
            audit = conn.execute(
                "SELECT action, actor FROM booking_audit ORDER BY id DESC LIMIT 1"
            ).fetchone()

        self.assertEqual(remaining, 0)
        self.assertEqual(audit, ("cancel", "admin"))
        mock_send_cancel.assert_called_once()

    @patch("event_management.services.booking_service.send_booking_confirmation_email")
    def test_resend_confirmation_email_updates_status(self, mock_send_confirmation):
        mock_send_confirmation.return_value = ("failed", "SMTP unavailable")
        event_id = self._create_event(capacity=3)
        booking_id = self._insert_booking(event_id, user_name="Alex", tickets=1, reference_code="RESEND0001")

        result = resend_confirmation_email(app, booking_id)
        self.assertEqual(result, {"status": "failed"})

        with closing(sqlite3.connect(self.db_path)) as conn:
            row = conn.execute(
                "SELECT confirmation_email_status, confirmation_email_error FROM bookings WHERE id = ?",
                (booking_id,),
            ).fetchone()

        self.assertEqual(row[0], "failed")
        self.assertIn("SMTP", row[1])

    def test_resend_confirmation_email_not_found(self):
        result = resend_confirmation_email(app, 99999)
        self.assertEqual(result, {"status": "not_found"})


if __name__ == "__main__":
    unittest.main()
