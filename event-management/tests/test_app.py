import os
import re
import sqlite3
import tempfile
import unittest

from app import app, init_db


class EventManagementAppTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)

        app.config["TESTING"] = True
        app.config["DATABASE"] = self.db_path
        app.config["SECRET_KEY"] = "test-secret"
        app.config["ADMIN_USERNAME"] = "admin"
        app.config["ADMIN_PASSWORD"] = "admin123"
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

    def _create_event(self, name="Tech Meetup", date="2026-03-01", location="Austin"):
        response = self._post_with_csrf(
            "/add_event",
            {"name": name, "date": date, "location": location},
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

    def test_post_without_csrf_token_rejected(self):
        self._logout_admin()
        response = self.client.post(
            "/login",
            data={"username": "admin", "password": "admin123"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 400)

    def test_add_event_success(self):
        response = self._post_with_csrf(
            "/add_event",
            {"name": "Hack Night", "date": "2026-03-02", "location": "Seattle"},
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
            {"name": "Blocked", "date": "2026-03-02", "location": "Seattle"},
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

    def test_login_page_does_not_render_admin_password(self):
        self._logout_admin()
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(app.config["ADMIN_PASSWORD"].encode("utf-8"), response.data)
        self.assertIn(b"Password is not displayed for security.", response.data)

    def test_add_event_validation_error(self):
        response = self._post_with_csrf(
            "/add_event",
            {"name": "", "date": "2026-03-02", "location": "Seattle"},
            get_path="/",
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Event name, date, and location are required.", response.data)

    def test_add_event_valid_date_format(self):
        response = self._post_with_csrf(
            "/add_event",
            {"name": "Format Pass", "date": "2026-12-31", "location": "Denver"},
            get_path="/",
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Event added successfully.", response.data)

    def test_add_event_invalid_date_format(self):
        response = self._post_with_csrf(
            "/add_event",
            {"name": "Format Fail", "date": "31-12-2026", "location": "Denver"},
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
        event_id = self._create_event(name="Old Name", date="2026-04-01", location="LA")

        response = self._post_with_csrf(
            f"/edit_event/{event_id}",
            {"name": "New Name", "date": "2026-04-20", "location": "SF"},
            get_path=f"/edit_event/{event_id}",
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Event updated successfully.", response.data)

        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT name, date, location FROM events WHERE id = ?",
                (event_id,),
            ).fetchone()

        self.assertEqual(row, ("New Name", "2026-04-20", "SF"))

    def test_edit_event_invalid_date(self):
        event_id = self._create_event(name="Old Name", date="2026-04-01", location="LA")

        response = self._post_with_csrf(
            f"/edit_event/{event_id}",
            {"name": "New Name", "date": "20-04-2026", "location": "SF"},
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
                "SELECT user_name, tickets FROM bookings WHERE event_id = ?",
                (event_id,),
            ).fetchone()

        self.assertEqual(row, ("Sonam", 3))

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
        self.assertIn("booking_id,event_name,user_name,tickets,created_at", csv_text)
        self.assertIn("Expo", csv_text)
        self.assertIn("Chris", csv_text)

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


if __name__ == "__main__":
    unittest.main()
