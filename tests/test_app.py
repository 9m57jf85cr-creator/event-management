import os
import re
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from app import app, init_db, load_runtime_config, reset_rate_limit_state


class EventManagementAppTests(unittest.TestCase):
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
        self._login_admin()

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def _extract_csrf_token(self, path):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")
        match = re.search(r'name="csrf_token" value="([^"]+)"', html)
        self.assertIsNotNone(match)
        return match.group(1)

    def _post_with_csrf(self, post_path, data, get_path=None, follow_redirects=True):
        token = self._extract_csrf_token(get_path or post_path)
        payload = dict(data)
        if post_path.startswith("/book/"):
            payload.setdefault("email", "user@example.com")
            payload.setdefault("phone", "+1 555 123 4567")
        payload["csrf_token"] = token
        return self.client.post(post_path, data=payload, follow_redirects=follow_redirects)

    def _login_admin(self):
        response = self._post_with_csrf(
            "/login",
            {"username": "admin", "password": "admin123", "next": ""},
            get_path="/login",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)

    def _logout_admin(self):
        response = self._post_with_csrf(
            "/logout",
            {},
            get_path="/",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)

    def _create_event(self, name="Tech Meetup", date="2026-03-01", location="Austin", capacity="100"):
        response = self._post_with_csrf(
            "/add_event",
            {"name": name, "date": date, "location": location, "capacity": capacity},
            get_path="/",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)

        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT id FROM events WHERE name = ? AND date = ? AND location = ?",
                (name, date, location),
            ).fetchone()

        self.assertIsNotNone(row)
        return row[0]

    def _get_booking_reference(self, event_id, user_name):
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT reference_code FROM bookings WHERE event_id = ? AND user_name = ? ORDER BY id DESC",
                (event_id, user_name),
            ).fetchone()
        self.assertIsNotNone(row)
        return row[0]

    def _get_latest_audit_row(self):
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                """
                SELECT booking_id, reference_code, action, actor
                FROM booking_audit
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()
        self.assertIsNotNone(row)
        return row

    def _api_headers(self, override_key=None):
        key = app.config["API_KEY"] if override_key is None else override_key
        return {"X-API-Key": key}

    def test_post_without_csrf_token_rejected(self):
        self._logout_admin()
        response = self.client.post(
            "/login",
            data={"username": "admin", "password": "admin123"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 400)

    def test_security_headers_present_on_html_response(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(response.headers.get("Referrer-Policy"), "no-referrer-when-downgrade")
        self.assertIn("frame-ancestors 'none'", response.headers.get("Content-Security-Policy", ""))

    def test_add_event_success(self):
        response = self._post_with_csrf(
            "/add_event",
            {"name": "Hack Night", "date": "2026-03-02", "location": "Seattle", "capacity": "100"},
            get_path="/",
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Event added successfully.", response.data)

        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

        self.assertEqual(count, 1)

    def test_protected_route_requires_admin(self):
        self._logout_admin()
        response = self._post_with_csrf(
            "/add_event",
            {"name": "Blocked", "date": "2026-03-02", "location": "Seattle", "capacity": "100"},
            get_path="/login",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Admin login required.", response.data)
        self.assertIn(b"Admin Login", response.data)

    def test_login_invalid_credentials(self):
        self._logout_admin()
        response = self._post_with_csrf(
            "/login",
            {"username": "wrong", "password": "wrong", "next": ""},
            get_path="/login",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid admin credentials.", response.data)

    def test_login_rate_limit_exceeded(self):
        self._logout_admin()
        app.config["RATE_LIMIT_LOGIN_MAX_REQUESTS"] = 2
        reset_rate_limit_state()

        first = self._post_with_csrf(
            "/login",
            {"username": "wrong", "password": "wrong", "next": ""},
            get_path="/login",
            follow_redirects=False,
        )
        self.assertEqual(first.status_code, 200)

        second = self._post_with_csrf(
            "/login",
            {"username": "wrong", "password": "wrong", "next": ""},
            get_path="/login",
            follow_redirects=False,
        )
        self.assertEqual(second.status_code, 200)

        third = self._post_with_csrf(
            "/login",
            {"username": "wrong", "password": "wrong", "next": ""},
            get_path="/login",
            follow_redirects=False,
        )
        self.assertEqual(third.status_code, 429)
        self.assertIn(b"Too many login attempts", third.data)

    def test_login_rate_limit_persists_across_clients(self):
        self._logout_admin()
        app.config["RATE_LIMIT_LOGIN_MAX_REQUESTS"] = 2
        reset_rate_limit_state()

        self._post_with_csrf(
            "/login",
            {"username": "wrong", "password": "wrong", "next": ""},
            get_path="/login",
            follow_redirects=False,
        )
        self._post_with_csrf(
            "/login",
            {"username": "wrong", "password": "wrong", "next": ""},
            get_path="/login",
            follow_redirects=False,
        )

        new_client = app.test_client()
        login_page = new_client.get("/login")
        self.assertEqual(login_page.status_code, 200)
        html = login_page.data.decode("utf-8")
        token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
        blocked = new_client.post(
            "/login",
            data={"username": "wrong", "password": "wrong", "next": "", "csrf_token": token},
            follow_redirects=False,
        )
        self.assertEqual(blocked.status_code, 429)
        self.assertIn(b"Too many login attempts", blocked.data)

    def test_login_rotates_session_csrf_token(self):
        self._logout_admin()
        old_token = self._extract_csrf_token("/login")
        with self.client.session_transaction() as sess:
            old_session_token = sess.get("_csrf_token")
        self.assertEqual(old_token, old_session_token)

        response = self.client.post(
            "/login",
            data={"username": "admin", "password": "admin123", "next": "", "csrf_token": old_token},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        with self.client.session_transaction() as sess:
            new_session_token = sess.get("_csrf_token")
            self.assertTrue(sess.get("is_admin"))
            self.assertTrue(sess.permanent)

        self.assertNotEqual(old_session_token, new_session_token)

    def test_login_rejects_external_next_url(self):
        self._logout_admin()
        response = self._post_with_csrf(
            "/login",
            {"username": "admin", "password": "admin123", "next": "//evil.example"},
            get_path="/login",
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers.get("Location"), "/")

    def test_login_page_does_not_render_admin_password(self):
        self._logout_admin()
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(app.config["ADMIN_PASSWORD"].encode("utf-8"), response.data)
        self.assertIn(b"Password is not displayed for security.", response.data)

    def test_add_event_validation_error(self):
        response = self._post_with_csrf(
            "/add_event",
            {"name": "", "date": "2026-03-02", "location": "Seattle", "capacity": "100"},
            get_path="/",
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Event name, date, and location are required.", response.data)

    def test_add_event_name_too_long(self):
        response = self._post_with_csrf(
            "/add_event",
            {"name": "A" * 121, "date": "2026-03-02", "location": "Seattle", "capacity": "100"},
            get_path="/",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Event name cannot exceed 120 characters.", response.data)

    def test_add_event_invalid_control_characters(self):
        response = self._post_with_csrf(
            "/add_event",
            {"name": "Hack\x01Night", "date": "2026-03-02", "location": "Seattle", "capacity": "100"},
            get_path="/",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Event fields contain invalid characters.", response.data)

    def test_add_event_valid_date_format(self):
        response = self._post_with_csrf(
            "/add_event",
            {"name": "Format Pass", "date": "2026-12-31", "location": "Denver", "capacity": "100"},
            get_path="/",
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Event added successfully.", response.data)

    def test_add_event_invalid_date_format(self):
        response = self._post_with_csrf(
            "/add_event",
            {"name": "Format Fail", "date": "31-12-2026", "location": "Denver", "capacity": "100"},
            get_path="/",
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Date must be in YYYY-MM-DD format.", response.data)

        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM events WHERE name = ?",
                ("Format Fail",),
            ).fetchone()[0]

        self.assertEqual(count, 0)

    def test_delete_event(self):
        event_id = self._create_event()

        response = self._post_with_csrf(
            f"/delete/{event_id}",
            {},
            get_path="/",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Event deleted.", response.data)

        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

        self.assertEqual(count, 0)

    def test_delete_event_get_not_allowed(self):
        event_id = self._create_event()
        response = self.client.get(f"/delete/{event_id}", follow_redirects=False)
        self.assertEqual(response.status_code, 405)

    def test_edit_event_success(self):
        event_id = self._create_event(name="Old Name", date="2026-04-01", location="LA", capacity="120")

        response = self._post_with_csrf(
            f"/edit_event/{event_id}",
            {"name": "New Name", "date": "2026-04-20", "location": "SF", "capacity": "150"},
            get_path=f"/edit_event/{event_id}",
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Event updated successfully.", response.data)

        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT name, date, location, capacity FROM events WHERE id = ?",
                (event_id,),
            ).fetchone()

        self.assertEqual(row, ("New Name", "2026-04-20", "SF", 150))

    def test_edit_event_invalid_date(self):
        event_id = self._create_event(name="Old Name", date="2026-04-01", location="LA")

        response = self._post_with_csrf(
            f"/edit_event/{event_id}",
            {"name": "New Name", "date": "20-04-2026", "location": "SF", "capacity": "100"},
            get_path=f"/edit_event/{event_id}",
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Date must be in YYYY-MM-DD format.", response.data)

    def test_edit_event_not_found(self):
        response = self.client.get("/edit_event/99999", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Event not found.", response.data)

    def test_booking_flow_success(self):
        event_id = self._create_event()

        response = self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "Sonam", "tickets": "3"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Booking successful.", response.data)

        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT user_name, tickets, reference_code FROM bookings WHERE event_id = ?",
                (event_id,),
            ).fetchone()

        self.assertEqual(row[0], "Sonam")
        self.assertEqual(row[1], 3)
        self.assertRegex(row[2], r"^[A-Z0-9]{10}$")
        self.assertIn(b"Your reference code:", response.data)

    def test_booking_validation_error(self):
        event_id = self._create_event()

        response = self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "Sonam", "tickets": "0"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Tickets must be a positive integer.", response.data)

    def test_booking_rate_limit_exceeded(self):
        event_id = self._create_event()
        app.config["RATE_LIMIT_BOOKING_MAX_REQUESTS"] = 2
        reset_rate_limit_state()

        first = self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "Sonam", "tickets": "1"},
            get_path=f"/book/{event_id}",
            follow_redirects=False,
        )
        self.assertEqual(first.status_code, 302)

        second = self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "Sonam", "tickets": "1"},
            get_path=f"/book/{event_id}",
            follow_redirects=False,
        )
        self.assertEqual(second.status_code, 302)

        third = self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "Sonam", "tickets": "1"},
            get_path=f"/book/{event_id}",
            follow_redirects=False,
        )
        self.assertEqual(third.status_code, 429)
        self.assertIn(b"Too many booking attempts", third.data)

    def test_rate_limit_scopes_are_independent(self):
        event_id = self._create_event()
        app.config["RATE_LIMIT_LOGIN_MAX_REQUESTS"] = 1
        app.config["RATE_LIMIT_BOOKING_MAX_REQUESTS"] = 1
        reset_rate_limit_state()

        self._logout_admin()
        first_login = self._post_with_csrf(
            "/login",
            {"username": "wrong", "password": "wrong", "next": ""},
            get_path="/login",
            follow_redirects=False,
        )
        self.assertEqual(first_login.status_code, 200)

        second_login = self._post_with_csrf(
            "/login",
            {"username": "wrong", "password": "wrong", "next": ""},
            get_path="/login",
            follow_redirects=False,
        )
        self.assertEqual(second_login.status_code, 429)

        booking_attempt = self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "Sonam", "tickets": "1"},
            get_path=f"/book/{event_id}",
            follow_redirects=False,
        )
        self.assertEqual(booking_attempt.status_code, 302)

    def test_booking_validation_tickets_too_high(self):
        event_id = self._create_event()
        response = self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "Sonam", "tickets": "101"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Tickets cannot exceed 100.", response.data)

    def test_booking_rejected_when_tickets_exceed_remaining_capacity(self):
        event_id = self._create_event(capacity="2")
        self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "First", "tickets": "1"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )

        response = self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "Second", "tickets": "2"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Only 1 tickets left for this event.", response.data)

    def test_booking_rejected_when_event_sold_out(self):
        event_id = self._create_event(capacity="1")
        self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "First", "tickets": "1"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )

        response = self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "Second", "tickets": "1"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"This event is sold out.", response.data)

    def test_home_page_shows_sold_out_state(self):
        event_id = self._create_event(name="Sold Out Event", capacity="1")
        self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "OnlyUser", "tickets": "1"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )

        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Remaining Tickets: 0", response.data)
        self.assertIn(b"Sold Out", response.data)

    def test_api_events_returns_expected_schema(self):
        event_id = self._create_event(name="API Event", date="2026-11-01", location="NYC", capacity="5")
        self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "ApiUser", "tickets": "2"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )

        response = self.client.get("/api/events", headers=self._api_headers())
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertIn("items", payload)
        self.assertIn("page", payload)
        self.assertIn("per_page", payload)
        self.assertIn("total_items", payload)
        self.assertIn("total_pages", payload)
        api_event = next(item for item in payload["items"] if item["id"] == event_id)
        self.assertEqual(api_event["name"], "API Event")
        self.assertEqual(api_event["capacity"], 5)
        self.assertEqual(api_event["total_tickets"], 2)
        self.assertEqual(api_event["remaining_tickets"], 3)
        self.assertFalse(api_event["is_sold_out"])

    def test_api_events_filters_by_query_and_date_range(self):
        self._create_event(name="AI Summit", date="2026-10-01", location="San Francisco", capacity="10")
        self._create_event(name="Music Fest", date="2026-12-01", location="Austin", capacity="10")

        response = self.client.get(
            "/api/events?q=Summit&date_from=2026-09-01&date_to=2026-10-31",
            headers=self._api_headers(),
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(len(payload["items"]), 1)
        self.assertEqual(payload["items"][0]["name"], "AI Summit")

    def test_api_events_pagination(self):
        for i in range(25):
            self._create_event(
                name=f"Paged API {i}",
                date=f"2026-11-{(i % 28) + 1:02d}",
                location="Remote",
                capacity="20",
            )

        response = self.client.get("/api/events?page=2&per_page=10", headers=self._api_headers())
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["page"], 2)
        self.assertEqual(payload["per_page"], 10)
        self.assertEqual(len(payload["items"]), 10)
        self.assertGreaterEqual(payload["total_items"], 25)

    def test_api_events_sold_out_flag(self):
        event_id = self._create_event(name="API Sold Out", date="2026-11-20", location="Delhi", capacity="1")
        self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "Buyer", "tickets": "1"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )

        response = self.client.get("/api/events?q=API%20Sold%20Out", headers=self._api_headers())
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(len(payload["items"]), 1)
        self.assertTrue(payload["items"][0]["is_sold_out"])
        self.assertEqual(payload["items"][0]["remaining_tickets"], 0)

    def test_api_events_invalid_date_filter_returns_400(self):
        response = self.client.get(
            "/api/events?date_from=31-12-2026",
            headers=self._api_headers(),
        )
        self.assertEqual(response.status_code, 400)

    def test_api_requires_key(self):
        response = self.client.get("/api/events")
        self.assertEqual(response.status_code, 401)

    def test_api_rejects_invalid_key(self):
        response = self.client.get("/api/events", headers=self._api_headers(override_key="bad-key"))
        self.assertEqual(response.status_code, 401)

    def test_api_v1_events_works_with_key(self):
        self._create_event(name="Versioned API Event", date="2026-11-15", location="SF", capacity="3")
        response = self.client.get("/api/v1/events", headers=self._api_headers())
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertIn("items", payload)
        self.assertGreaterEqual(len(payload["items"]), 1)

    def test_api_v1_health_works_with_key(self):
        response = self.client.get("/api/v1/health", headers=self._api_headers())
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["version"], "v1")

    def test_booking_validation_name_too_long(self):
        event_id = self._create_event()
        response = self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "A" * 81, "tickets": "1"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Name cannot exceed 80 characters.", response.data)

    def test_booking_validation_invalid_control_characters(self):
        event_id = self._create_event()
        response = self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "User\x01", "tickets": "1"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Name contains invalid characters.", response.data)

    def test_booking_validation_invalid_email(self):
        event_id = self._create_event()
        response = self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "User", "email": "bad-email", "phone": "+1 555 123 4567", "tickets": "1"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Enter a valid email address.", response.data)

    def test_booking_validation_invalid_phone(self):
        event_id = self._create_event()
        response = self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "User", "email": "user@example.com", "phone": "12", "tickets": "1"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Enter a valid phone number.", response.data)

    def test_my_bookings_page_loads_for_non_admin(self):
        self._logout_admin()
        response = self.client.get("/my_bookings")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"My Bookings", response.data)
        self.assertIn(b"Find Bookings", response.data)

    def test_my_bookings_lookup_by_name(self):
        event_id = self._create_event(name="Community Meetup", date="2026-06-15", location="Boston")
        self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "Alex", "tickets": "2"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )
        self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "Nima", "tickets": "1"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )

        self._logout_admin()
        reference_code = self._get_booking_reference(event_id, "Alex")

        response = self.client.get(f"/my_bookings?ref={reference_code}")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Community Meetup", response.data)
        self.assertIn(b"Alex", response.data)
        self.assertIn(b"user@example.com", response.data)
        self.assertIn(b"+1 555 123 4567", response.data)
        self.assertNotIn(b"Nima", response.data)
        self.assertIn(reference_code.encode("utf-8"), response.data)

    def test_my_bookings_cancel_success(self):
        event_id = self._create_event(name="Expo", date="2026-06-20", location="NYC")
        self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "Chris", "tickets": "2"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )

        reference_code = self._get_booking_reference(event_id, "Chris")

        self._logout_admin()
        response = self._post_with_csrf(
            f"/my_bookings/cancel/{reference_code}",
            {},
            get_path=f"/my_bookings?ref={reference_code}",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Your booking was cancelled.", response.data)

        with sqlite3.connect(self.db_path) as conn:
            remaining = conn.execute(
                "SELECT COUNT(*) FROM bookings WHERE reference_code = ?",
                (reference_code,),
            ).fetchone()[0]
        self.assertEqual(remaining, 0)

        audit_row = self._get_latest_audit_row()
        self.assertEqual(audit_row[1], reference_code)
        self.assertEqual(audit_row[2], "cancel")
        self.assertEqual(audit_row[3], "self_service")

    def test_my_bookings_cancel_rejects_wrong_name(self):
        event_id = self._create_event(name="Expo", date="2026-06-20", location="NYC")
        self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "Chris", "tickets": "2"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )

        reference_code = self._get_booking_reference(event_id, "Chris")

        self._logout_admin()
        response = self._post_with_csrf(
            "/my_bookings/cancel/INVALID!",
            {},
            get_path=f"/my_bookings?ref={reference_code}",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid booking reference code.", response.data)

        with sqlite3.connect(self.db_path) as conn:
            remaining = conn.execute(
                "SELECT COUNT(*) FROM bookings WHERE reference_code = ?",
                (reference_code,),
            ).fetchone()[0]
        self.assertEqual(remaining, 1)

    def test_my_bookings_cancel_rejects_unknown_reference_code(self):
        event_id = self._create_event(name="Expo", date="2026-06-20", location="NYC")
        self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "Chris", "tickets": "2"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )

        self._logout_admin()
        response = self._post_with_csrf(
            "/my_bookings/cancel/AAAAAAAAAA",
            {},
            get_path="/login",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Booking not found for this reference code.", response.data)

    def test_bookings_page_empty_state(self):
        response = self.client.get("/bookings")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"No bookings yet.", response.data)

    def test_bookings_page_lists_booking(self):
        event_id = self._create_event(name="Conference", date="2026-06-01", location="Boston")
        self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "Alex", "tickets": "2"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )

        response = self.client.get("/bookings")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Conference", response.data)
        self.assertIn(b"Alex", response.data)
        self.assertIn(b"user@example.com", response.data)
        self.assertIn(b"+1 555 123 4567", response.data)
        self.assertIn(b"2", response.data)
        self.assertIn(b"Booked At:", response.data)

    def test_bookings_search_filters_results(self):
        event_a = self._create_event(name="Conference", date="2026-06-01", location="Boston")
        event_b = self._create_event(name="Hackday", date="2026-06-02", location="Austin")
        self._post_with_csrf(
            f"/book/{event_a}",
            {"name": "Alex", "tickets": "2"},
            get_path=f"/book/{event_a}",
            follow_redirects=True,
        )
        self._post_with_csrf(
            f"/book/{event_b}",
            {"name": "Nima", "tickets": "1"},
            get_path=f"/book/{event_b}",
            follow_redirects=True,
        )

        response = self.client.get("/bookings?q=Alex")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Alex", response.data)
        self.assertNotIn(b"Nima", response.data)

    def test_bookings_pagination_controls(self):
        event_id = self._create_event(name="Paged Event", date="2026-07-01", location="Remote")
        for i in range(11):
            self._post_with_csrf(
                f"/book/{event_id}",
                {"name": f"User{i}", "tickets": "1"},
                get_path=f"/book/{event_id}",
                follow_redirects=True,
            )

        page1 = self.client.get("/bookings?page=1")
        self.assertEqual(page1.status_code, 200)
        self.assertIn(b"Page 1 of 2", page1.data)
        self.assertIn(b"Next", page1.data)

        page2 = self.client.get("/bookings?page=2")
        self.assertEqual(page2.status_code, 200)
        self.assertIn(b"Page 2 of 2", page2.data)
        self.assertIn(b"Prev", page2.data)

    def test_bookings_sort_by_tickets_asc(self):
        event_id = self._create_event(name="Sort Event", date="2026-07-05", location="Remote")
        self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "HighTicketUser", "tickets": "5"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )
        self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "LowTicketUser", "tickets": "1"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )

        response = self.client.get("/bookings?sort_by=tickets&sort_dir=asc")
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")
        self.assertLess(html.find("LowTicketUser"), html.find("HighTicketUser"))

    def test_bookings_invalid_sort_falls_back_to_default(self):
        event_id = self._create_event(name="Fallback Event", date="2026-07-06", location="Remote")
        self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "UserFallback", "tickets": "1"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )

        response = self.client.get("/bookings?sort_by=__bad__&sort_dir=__bad__")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'value="created_at" selected', response.data)
        self.assertIn(b'value="desc" selected', response.data)

    def test_cancel_booking_success(self):
        event_id = self._create_event(name="Summit", date="2026-08-01", location="Denver")
        self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "Nima", "tickets": "1"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )

        with sqlite3.connect(self.db_path) as conn:
            booking_id = conn.execute(
                "SELECT id FROM bookings WHERE event_id = ?",
                (event_id,),
            ).fetchone()[0]

        response = self._post_with_csrf(
            f"/cancel_booking/{booking_id}",
            {},
            get_path="/bookings",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Booking cancelled.", response.data)

        with sqlite3.connect(self.db_path) as conn:
            remaining = conn.execute(
                "SELECT COUNT(*) FROM bookings WHERE id = ?",
                (booking_id,),
            ).fetchone()[0]

        self.assertEqual(remaining, 0)

        audit_row = self._get_latest_audit_row()
        self.assertEqual(audit_row[0], booking_id)
        self.assertEqual(audit_row[2], "cancel")
        self.assertEqual(audit_row[3], "admin")

    def test_cancel_booking_not_found(self):
        response = self._post_with_csrf(
            "/cancel_booking/99999",
            {},
            get_path="/bookings",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Booking not found.", response.data)

    def test_export_bookings_csv(self):
        event_id = self._create_event(name="Expo", date="2026-09-10", location="NYC")
        self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "Chris", "tickets": "4"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )

        response = self.client.get("/bookings/export.csv")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("Content-Type"), "text/csv; charset=utf-8")
        self.assertIn("attachment; filename=bookings_report.csv", response.headers.get("Content-Disposition", ""))
        csv_text = response.data.decode("utf-8")
        self.assertIn(
            "booking_id,event_name,user_name,user_email,user_phone,tickets,created_at,reference_code",
            csv_text,
        )
        self.assertIn("Expo", csv_text)
        self.assertIn("Chris", csv_text)
        self.assertIn("user@example.com", csv_text)
        self.assertIn("+1 555 123 4567", csv_text)

    def test_export_bookings_csv_respects_search_filter(self):
        event_a = self._create_event(name="Expo", date="2026-09-10", location="NYC")
        event_b = self._create_event(name="Summit", date="2026-09-11", location="SF")
        self._post_with_csrf(
            f"/book/{event_a}",
            {"name": "Chris", "tickets": "4"},
            get_path=f"/book/{event_a}",
            follow_redirects=True,
        )
        self._post_with_csrf(
            f"/book/{event_b}",
            {"name": "Alex", "tickets": "2"},
            get_path=f"/book/{event_b}",
            follow_redirects=True,
        )

        response = self.client.get("/bookings/export.csv?q=Chris")
        self.assertEqual(response.status_code, 200)
        csv_text = response.data.decode("utf-8")
        self.assertIn("Chris", csv_text)
        self.assertNotIn("Alex", csv_text)

    def test_export_bookings_csv_respects_sort_order(self):
        event_id = self._create_event(name="Sort CSV Event", date="2026-09-12", location="LA")
        self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "HighCSV", "tickets": "6"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )
        self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "LowCSV", "tickets": "1"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )

        response = self.client.get("/bookings/export.csv?sort_by=tickets&sort_dir=asc")
        self.assertEqual(response.status_code, 200)
        csv_text = response.data.decode("utf-8")
        self.assertLess(csv_text.find("LowCSV"), csv_text.find("HighCSV"))

    def test_export_bookings_csv_requires_admin(self):
        self._logout_admin()
        response = self.client.get("/bookings/export.csv", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Admin login required.", response.data)

    def test_booking_audit_page_lists_entries(self):
        event_id = self._create_event(name="Audit Event", date="2026-10-01", location="NYC")
        self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "AuditedUser", "tickets": "1"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )
        reference_code = self._get_booking_reference(event_id, "AuditedUser")
        with sqlite3.connect(self.db_path) as conn:
            booking_id = conn.execute(
                "SELECT id FROM bookings WHERE reference_code = ?",
                (reference_code,),
            ).fetchone()[0]

        self._post_with_csrf(
            f"/cancel_booking/{booking_id}",
            {},
            get_path="/bookings",
            follow_redirects=True,
        )

        response = self.client.get("/booking_audit")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Booking Audit", response.data)
        self.assertIn(reference_code.encode("utf-8"), response.data)
        self.assertIn(b"admin", response.data)

    def test_booking_audit_export_csv(self):
        event_id = self._create_event(name="Audit Export Event", date="2026-10-02", location="LA")
        self._post_with_csrf(
            f"/book/{event_id}",
            {"name": "ExportUser", "tickets": "1"},
            get_path=f"/book/{event_id}",
            follow_redirects=True,
        )
        reference_code = self._get_booking_reference(event_id, "ExportUser")

        booking_id = None
        with sqlite3.connect(self.db_path) as conn:
            booking_id = conn.execute(
                "SELECT id FROM bookings WHERE reference_code = ?",
                (reference_code,),
            ).fetchone()[0]

        self._post_with_csrf(
            f"/cancel_booking/{booking_id}",
            {},
            get_path="/bookings",
            follow_redirects=True,
        )

        response = self.client.get("/booking_audit/export.csv")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("Content-Type"), "text/csv; charset=utf-8")
        self.assertIn(
            "attachment; filename=booking_audit_report.csv",
            response.headers.get("Content-Disposition", ""),
        )
        csv_text = response.data.decode("utf-8")
        self.assertIn("booking_id,reference_code,action,actor,created_at", csv_text)
        self.assertIn(reference_code, csv_text)
        self.assertIn("cancel", csv_text)

    def test_booking_audit_page_requires_admin(self):
        self._logout_admin()
        response = self.client.get("/booking_audit", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Admin login required.", response.data)

    def test_load_runtime_config_rejects_empty_admin_credentials(self):
        with patch.dict(
            os.environ,
            {"ADMIN_USERNAME": "", "ADMIN_PASSWORD": "admin123"},
            clear=False,
        ):
            with self.assertRaises(RuntimeError):
                load_runtime_config()

    def test_load_runtime_config_rejects_default_secret_in_production(self):
        with patch.dict(
            os.environ,
            {
                "FLASK_ENV": "production",
                "SECRET_KEY": "dev-secret-key-change-me",
                "ADMIN_USERNAME": "admin",
                "ADMIN_PASSWORD": "admin123",
            },
            clear=False,
        ):
            with self.assertRaises(RuntimeError):
                load_runtime_config()

    def test_load_runtime_config_sets_production_secure_mode(self):
        with patch.dict(
            os.environ,
            {
                "FLASK_ENV": "production",
                "SECRET_KEY": "x" * 40,
                "ADMIN_USERNAME": "admin",
                "ADMIN_PASSWORD": "admin123",
                "DATABASE": "events.db",
            },
            clear=False,
        ):
            config = load_runtime_config()

        self.assertTrue(config["IS_PRODUCTION"])
        self.assertTrue(config["DATABASE"].endswith("events.db"))

    def test_load_runtime_config_rejects_invalid_rate_limit_window(self):
        with patch.dict(
            os.environ,
            {
                "RATE_LIMIT_WINDOW_SECONDS": "0",
                "ADMIN_USERNAME": "admin",
                "ADMIN_PASSWORD": "admin123",
            },
            clear=False,
        ):
            with self.assertRaises(RuntimeError):
                load_runtime_config()

    def test_load_runtime_config_rejects_empty_api_key(self):
        with patch.dict(
            os.environ,
            {
                "API_KEY": "",
                "ADMIN_USERNAME": "admin",
                "ADMIN_PASSWORD": "admin123",
            },
            clear=False,
        ):
            with self.assertRaises(RuntimeError):
                load_runtime_config()


if __name__ == "__main__":
    unittest.main()
