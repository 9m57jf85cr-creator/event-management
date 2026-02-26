import os
import re
import sqlite3
import tempfile
import unittest

from app import app, init_db, reset_rate_limit_state


class SmokeFlowTests(unittest.TestCase):
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
        reset_rate_limit_state()
        init_db()
        self.client = app.test_client()

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def _csrf_from_path(self, path):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")
        match = re.search(r'name="csrf_token" value="([^"]+)"', html)
        self.assertIsNotNone(match)
        return match.group(1)

    def _login_admin(self):
        token = self._csrf_from_path("/login")
        response = self.client.post(
            "/login",
            data={
                "username": app.config["ADMIN_USERNAME"],
                "password": app.config["ADMIN_PASSWORD"],
                "next": "",
                "csrf_token": token,
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)

    def test_end_to_end_smoke_flow(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)

        response = self.client.get("/api/v1/health")
        self.assertEqual(response.status_code, 401)
        response = self.client.get("/api/v1/health", headers={"X-API-Key": app.config["API_KEY"]})
        self.assertEqual(response.status_code, 200)

        self._login_admin()

        token = self._csrf_from_path("/")
        response = self.client.post(
            "/add_event",
            data={
                "name": "Smoke Test Event",
                "date": "2026-12-01",
                "location": "Test Hall",
                "capacity": "50",
                "csrf_token": token,
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Event added successfully.", response.data)

        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT id FROM events WHERE name = ?", ("Smoke Test Event",)).fetchone()
        self.assertIsNotNone(row)
        event_id = row[0]

        token = self._csrf_from_path(f"/book/{event_id}")
        response = self.client.post(
            f"/book/{event_id}",
            data={
                "name": "Smoke User",
                "email": "smoke@example.com",
                "phone": "+1 555 333 7777",
                "tickets": "2",
                "csrf_token": token,
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")
        match = re.search(r"reference code:\s*([A-Z0-9]{10})", html)
        self.assertIsNotNone(match)
        reference_code = match.group(1)

        response = self.client.get(f"/my_bookings?ref={reference_code}")
        self.assertEqual(response.status_code, 200)
        self.assertIn(reference_code.encode("utf-8"), response.data)

        token = self._csrf_from_path(f"/my_bookings?ref={reference_code}")
        response = self.client.post(
            f"/my_bookings/cancel/{reference_code}",
            data={"csrf_token": token},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"cancelled", response.data.lower())

        response = self.client.get("/bookings")
        self.assertEqual(response.status_code, 200)
        response = self.client.get("/bookings/export.csv")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.headers.get("Content-Type", ""))

        response = self.client.get("/booking_audit")
        self.assertEqual(response.status_code, 200)
        response = self.client.get("/booking_audit/export.csv")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/csv", response.headers.get("Content-Type", ""))
