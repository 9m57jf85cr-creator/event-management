from flask import Flask, abort, flash, make_response, redirect, render_template, request, session, url_for
from datetime import datetime
from datetime import timedelta
from functools import wraps
import csv
import io
import os
import secrets
import sqlite3

DEFAULT_SECRET_KEY = "dev-secret-key-change-me"
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
MAX_EVENT_NAME_LENGTH = 120
MAX_LOCATION_LENGTH = 120
MAX_BOOKING_NAME_LENGTH = 80
MAX_TICKETS = 100


def _load_dotenv(path=".env"):
    if not os.path.exists(path):
        return

    with open(path, encoding="utf-8") as dotenv_file:
        for raw_line in dotenv_file:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key:
                os.environ.setdefault(key, value)


_load_dotenv()


def _is_production_environment():
    return os.getenv("FLASK_ENV", "development").strip().lower() == "production"


def _resolve_database_path(database_value):
    database_path = database_value.strip() or "events.db"
    if os.path.isabs(database_path):
        return database_path
    return os.path.join(PROJECT_ROOT, database_path)


def load_runtime_config():
    is_production = _is_production_environment()
    secret_key = os.getenv("SECRET_KEY", DEFAULT_SECRET_KEY)
    admin_username = os.getenv("ADMIN_USERNAME", "admin").strip()
    admin_password = os.getenv("ADMIN_PASSWORD", "admin123")
    database = _resolve_database_path(os.getenv("DATABASE", "events.db"))

    if not admin_username or not admin_password:
        raise RuntimeError("ADMIN_USERNAME and ADMIN_PASSWORD must be set.")

    if is_production and secret_key == DEFAULT_SECRET_KEY:
        raise RuntimeError("SECRET_KEY must be changed in production.")

    return {
        "SECRET_KEY": secret_key,
        "DATABASE": database,
        "ADMIN_USERNAME": admin_username,
        "ADMIN_PASSWORD": admin_password,
        "IS_PRODUCTION": is_production,
    }


app = Flask(__name__)
app.config.update(load_runtime_config())
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = app.config["IS_PRODUCTION"]
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)


def get_db_connection():
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _migrate_bookings_table(cursor):
    cursor.execute("PRAGMA foreign_key_list(bookings)")
    has_fk = bool(cursor.fetchall())
    if has_fk:
        return

    cursor.execute("""
        CREATE TABLE bookings_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            user_name TEXT NOT NULL,
            tickets INTEGER NOT NULL,
            FOREIGN KEY (event_id) REFERENCES events (id) ON DELETE CASCADE
        )
    """)
    cursor.execute("""
        INSERT INTO bookings_new (id, event_id, user_name, tickets)
        SELECT b.id, b.event_id, b.user_name, b.tickets
        FROM bookings b
        JOIN events e ON e.id = b.event_id
    """)
    cursor.execute("DROP TABLE bookings")
    cursor.execute("ALTER TABLE bookings_new RENAME TO bookings")


def _ensure_bookings_created_at(cursor):
    cursor.execute("PRAGMA table_info(bookings)")
    columns = {row[1] for row in cursor.fetchall()}
    if "created_at" not in columns:
        cursor.execute(
            "ALTER TABLE bookings ADD COLUMN created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
        )


def _parse_event_form():
    name = request.form.get("name", "").strip()
    date = request.form.get("date", "").strip()
    location = request.form.get("location", "").strip()
    return name, date, location


def _validate_event_fields(name, date, location):
    if not name or not date or not location:
        flash("Event name, date, and location are required.", "error")
        return False

    if len(name) > MAX_EVENT_NAME_LENGTH:
        flash(f"Event name cannot exceed {MAX_EVENT_NAME_LENGTH} characters.", "error")
        return False

    if len(location) > MAX_LOCATION_LENGTH:
        flash(f"Location cannot exceed {MAX_LOCATION_LENGTH} characters.", "error")
        return False

    if any(ord(ch) < 32 for ch in name + location):
        flash("Event fields contain invalid characters.", "error")
        return False

    try:
        datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        flash("Date must be in YYYY-MM-DD format.", "error")
        return False

    return True


def _parse_booking_sort():
    allowed_sort_fields = {
        "created_at": "b.created_at",
        "event_name": "e.name",
        "user_name": "b.user_name",
        "tickets": "b.tickets",
    }
    sort_by = request.args.get("sort_by", "created_at").strip()
    if sort_by not in allowed_sort_fields:
        sort_by = "created_at"

    sort_dir = request.args.get("sort_dir", "desc").strip().lower()
    if sort_dir not in {"asc", "desc"}:
        sort_dir = "desc"

    order_by_sql = f"{allowed_sort_fields[sort_by]} {sort_dir.upper()}, b.id DESC"
    return sort_by, sort_dir, order_by_sql


def admin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Admin login required.", "error")
            return redirect(url_for("login", next=request.path))
        return view_func(*args, **kwargs)

    return wrapper


def _is_safe_next_url(next_url):
    return next_url.startswith("/") and not next_url.startswith("//")


def _credentials_match(username, password):
    expected_username = app.config["ADMIN_USERNAME"]
    expected_password = app.config["ADMIN_PASSWORD"]
    return (
        secrets.compare_digest(username.encode("utf-8"), expected_username.encode("utf-8"))
        and secrets.compare_digest(password.encode("utf-8"), expected_password.encode("utf-8"))
    )


def _generate_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": _generate_csrf_token}


@app.before_request
def protect_from_csrf():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return

    expected = session.get("_csrf_token", "")
    received = request.form.get("csrf_token", "")
    if not expected or not received or not secrets.compare_digest(expected, received):
        abort(400, description="Invalid CSRF token.")


@app.after_request
def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer-when-downgrade"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    return response


# Create or migrate database tables
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            date TEXT NOT NULL,
            location TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            user_name TEXT NOT NULL,
            tickets INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (event_id) REFERENCES events (id) ON DELETE CASCADE
        )
    """)

    _migrate_bookings_table(cursor)
    _ensure_bookings_created_at(cursor)
    conn.commit()
    conn.close()

init_db()


@app.route("/login", methods=["GET", "POST"])
def login():
    next_url = request.args.get("next", "")
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        next_url = request.form.get("next", "")

        if _credentials_match(username, password):
            session.clear()
            session["is_admin"] = True
            session.permanent = True
            _generate_csrf_token()
            flash("Logged in as admin.", "success")
            if _is_safe_next_url(next_url):
                return redirect(next_url)
            return redirect(url_for("home"))

        flash("Invalid admin credentials.", "error")

    return render_template(
        "login.html",
        next_url=next_url,
        admin_username=app.config["ADMIN_USERNAME"],
    )


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("home"))


# Home Page
@app.route("/")
def home():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT e.id, e.name, e.date, e.location, COALESCE(SUM(b.tickets), 0) AS total_tickets
        FROM events e
        LEFT JOIN bookings b ON e.id = b.event_id
        GROUP BY e.id, e.name, e.date, e.location
        ORDER BY e.date, e.id
    """)
    event_rows = cursor.fetchall()
    conn.close()
    event_data = [
        {
            "id": row[0],
            "name": row[1],
            "date": row[2],
            "location": row[3],
            "total_tickets": row[4],
        }
        for row in event_rows
    ]
    return render_template("index.html", event_data=event_data)


# Add Event
@app.route("/add_event", methods=["POST"])
@admin_required
def add_event():
    name, date, location = _parse_event_form()
    if not _validate_event_fields(name, date, location):
        return redirect(url_for("home"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO events (name, date, location) VALUES (?, ?, ?)",
                   (name, date, location))
    conn.commit()
    conn.close()

    flash("Event added successfully.", "success")
    return redirect(url_for("home"))


# Delete Event
@app.route("/delete/<int:id>", methods=["POST"])
@admin_required
def delete_event(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM events WHERE id = ?", (id,))
    if cursor.fetchone() is None:
        conn.close()
        flash("Event not found.", "error")
        return redirect(url_for("home"))

    cursor.execute("DELETE FROM events WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash("Event deleted.", "success")
    return redirect(url_for("home"))


@app.route("/edit_event/<int:event_id>", methods=["GET", "POST"])
@admin_required
def edit_event(event_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, date, location FROM events WHERE id = ?", (event_id,))
    row = cursor.fetchone()
    if row is None:
        conn.close()
        flash("Event not found.", "error")
        return redirect(url_for("home"))

    event = {"id": row[0], "name": row[1], "date": row[2], "location": row[3]}

    if request.method == "POST":
        name, date, location = _parse_event_form()
        if not _validate_event_fields(name, date, location):
            event = {"id": event_id, "name": name, "date": date, "location": location}
            conn.close()
            return render_template("edit_event.html", event=event)

        cursor.execute(
            "UPDATE events SET name = ?, date = ?, location = ? WHERE id = ?",
            (name, date, location, event_id),
        )
        conn.commit()
        conn.close()
        flash("Event updated successfully.", "success")
        return redirect(url_for("home"))

    conn.close()
    return render_template("edit_event.html", event=event)


# Book Event
@app.route("/book/<int:event_id>", methods=["GET", "POST"])
def book_event(event_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM events WHERE id = ?", (event_id,))
    event = cursor.fetchone()
    conn.close()
    if event is None:
        flash("Event not found.", "error")
        return redirect(url_for("home"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        tickets_raw = request.form.get("tickets", "").strip()

        if not name:
            flash("Your name is required.", "error")
            return redirect(url_for("book_event", event_id=event_id))

        if len(name) > MAX_BOOKING_NAME_LENGTH:
            flash(f"Name cannot exceed {MAX_BOOKING_NAME_LENGTH} characters.", "error")
            return redirect(url_for("book_event", event_id=event_id))

        if any(ord(ch) < 32 for ch in name):
            flash("Name contains invalid characters.", "error")
            return redirect(url_for("book_event", event_id=event_id))

        try:
            tickets = int(tickets_raw)
            if tickets <= 0:
                raise ValueError
        except ValueError:
            flash("Tickets must be a positive integer.", "error")
            return redirect(url_for("book_event", event_id=event_id))

        if tickets > MAX_TICKETS:
            flash(f"Tickets cannot exceed {MAX_TICKETS}.", "error")
            return redirect(url_for("book_event", event_id=event_id))

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO bookings (event_id, user_name, tickets) VALUES (?, ?, ?)",
                       (event_id, name, tickets))
        conn.commit()
        conn.close()

        flash("Booking successful.", "success")
        return redirect(url_for("home"))

    return render_template("book.html", event={"id": event[0], "name": event[1]})


@app.route("/bookings")
@admin_required
def bookings():
    query = request.args.get("q", "").strip()
    sort_by, sort_dir, order_by_sql = _parse_booking_sort()
    page = request.args.get("page", default=1, type=int)
    per_page = 10
    if page < 1:
        page = 1

    conn = get_db_connection()
    cursor = conn.cursor()
    where_clause = ""
    params = []
    if query:
        where_clause = "WHERE e.name LIKE ? OR b.user_name LIKE ?"
        pattern = f"%{query}%"
        params = [pattern, pattern]

    cursor.execute(
        f"""
        SELECT COUNT(*)
        FROM bookings b
        JOIN events e ON e.id = b.event_id
        {where_clause}
        """,
        params,
    )
    total_items = cursor.fetchone()[0]
    total_pages = max(1, (total_items + per_page - 1) // per_page)
    if page > total_pages:
        page = total_pages
    offset = (page - 1) * per_page

    cursor.execute(
        f"""
        SELECT b.id, e.name, b.user_name, b.tickets, b.created_at
        FROM bookings b
        JOIN events e ON e.id = b.event_id
        {where_clause}
        ORDER BY {order_by_sql}
        LIMIT ? OFFSET ?
        """,
        params + [per_page, offset],
    )
    booking_rows = cursor.fetchall()
    conn.close()
    booking_data = [
        {
            "id": row[0],
            "event_name": row[1],
            "user_name": row[2],
            "tickets": row[3],
            "created_at": row[4],
        }
        for row in booking_rows
    ]
    return render_template(
        "bookings.html",
        booking_data=booking_data,
        q=query,
        page=page,
        total_pages=total_pages,
        sort_by=sort_by,
        sort_dir=sort_dir,
    )


@app.route("/cancel_booking/<int:booking_id>", methods=["POST"])
@admin_required
def cancel_booking(booking_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM bookings WHERE id = ?", (booking_id,))
    if cursor.fetchone() is None:
        conn.close()
        flash("Booking not found.", "error")
        return redirect(url_for("bookings"))

    cursor.execute("DELETE FROM bookings WHERE id = ?", (booking_id,))
    conn.commit()
    conn.close()
    flash("Booking cancelled.", "success")
    return redirect(url_for("bookings"))


@app.route("/bookings/export.csv")
@admin_required
def export_bookings_csv():
    query = request.args.get("q", "").strip()
    _, _, order_by_sql = _parse_booking_sort()
    conn = get_db_connection()
    cursor = conn.cursor()
    where_clause = ""
    params = []
    if query:
        where_clause = "WHERE e.name LIKE ? OR b.user_name LIKE ?"
        pattern = f"%{query}%"
        params = [pattern, pattern]

    cursor.execute(
        f"""
        SELECT b.id, e.name, b.user_name, b.tickets, b.created_at
        FROM bookings b
        JOIN events e ON e.id = b.event_id
        {where_clause}
        ORDER BY {order_by_sql}
        """,
        params,
    )
    rows = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["booking_id", "event_name", "user_name", "tickets", "created_at"])
    writer.writerows(rows)

    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=bookings_report.csv"
    return response


def main():
    host = os.getenv("FLASK_HOST", "127.0.0.1")
    port = int(os.getenv("FLASK_PORT", "5000"))
    debug_env = os.getenv("FLASK_DEBUG", "").strip().lower()
    if debug_env in {"1", "true", "yes", "on"}:
        debug = True
    elif debug_env in {"0", "false", "no", "off"}:
        debug = False
    else:
        debug = not app.config["IS_PRODUCTION"]

    app.run(debug=debug, host=host, port=port)


if __name__ == "__main__":
    main()
