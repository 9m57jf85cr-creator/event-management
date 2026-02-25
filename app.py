from flask import Flask, abort, flash, make_response, redirect, render_template, request, session, url_for
from datetime import datetime
from datetime import timedelta
from functools import wraps
import csv
import io
import os
import secrets
import sqlite3
import string

DEFAULT_SECRET_KEY = "dev-secret-key-change-me"
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
MAX_EVENT_NAME_LENGTH = 120
MAX_LOCATION_LENGTH = 120
MAX_BOOKING_NAME_LENGTH = 80
MAX_TICKETS = 100
MAX_EVENT_CAPACITY = 5000
BOOKING_REFERENCE_LENGTH = 10


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


def _generate_booking_reference(cursor):
    alphabet = string.ascii_uppercase + string.digits
    while True:
        reference_code = "".join(secrets.choice(alphabet) for _ in range(BOOKING_REFERENCE_LENGTH))
        cursor.execute("SELECT 1 FROM bookings WHERE reference_code = ?", (reference_code,))
        if cursor.fetchone() is None:
            return reference_code


def _ensure_bookings_reference_code(cursor):
    cursor.execute("PRAGMA table_info(bookings)")
    columns = {row[1] for row in cursor.fetchall()}
    if "reference_code" not in columns:
        cursor.execute("ALTER TABLE bookings ADD COLUMN reference_code TEXT")

    cursor.execute("SELECT id FROM bookings WHERE reference_code IS NULL OR reference_code = ''")
    missing_rows = cursor.fetchall()
    for row in missing_rows:
        reference_code = _generate_booking_reference(cursor)
        cursor.execute(
            "UPDATE bookings SET reference_code = ? WHERE id = ?",
            (reference_code, row[0]),
        )

    cursor.execute("PRAGMA index_list(bookings)")
    indexes = {row[1] for row in cursor.fetchall()}
    if "idx_bookings_reference_code" not in indexes:
        cursor.execute(
            "CREATE UNIQUE INDEX idx_bookings_reference_code ON bookings(reference_code)"
        )


def _ensure_events_capacity(cursor):
    cursor.execute("PRAGMA table_info(events)")
    columns = {row[1] for row in cursor.fetchall()}
    if "capacity" not in columns:
        cursor.execute(
            f"ALTER TABLE events ADD COLUMN capacity INTEGER NOT NULL DEFAULT {MAX_TICKETS}"
        )
    cursor.execute(
        f"UPDATE events SET capacity = {MAX_TICKETS} WHERE capacity IS NULL OR capacity <= 0"
    )


def _ensure_booking_audit_table(cursor):
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


def _log_booking_audit(cursor, booking_id, reference_code, action, actor):
    cursor.execute(
        """
        INSERT INTO booking_audit (booking_id, reference_code, action, actor)
        VALUES (?, ?, ?, ?)
        """,
        (booking_id, reference_code, action, actor),
    )


def _parse_event_form(default_capacity=None):
    name = request.form.get("name", "").strip()
    date = request.form.get("date", "").strip()
    location = request.form.get("location", "").strip()
    capacity_raw = request.form.get("capacity")
    if capacity_raw is None:
        if default_capacity is not None:
            capacity_raw = str(default_capacity)
        else:
            capacity_raw = str(MAX_TICKETS)
    capacity = capacity_raw.strip()
    return name, date, location, capacity


def _validate_event_fields(name, date, location, capacity_raw):
    if not name or not date or not location:
        flash("Event name, date, and location are required.", "error")
        return False, None

    if len(name) > MAX_EVENT_NAME_LENGTH:
        flash(f"Event name cannot exceed {MAX_EVENT_NAME_LENGTH} characters.", "error")
        return False, None

    if len(location) > MAX_LOCATION_LENGTH:
        flash(f"Location cannot exceed {MAX_LOCATION_LENGTH} characters.", "error")
        return False, None

    if any(ord(ch) < 32 for ch in name + location):
        flash("Event fields contain invalid characters.", "error")
        return False, None

    try:
        capacity = int(capacity_raw)
    except ValueError:
        flash("Capacity must be a positive integer.", "error")
        return False, None

    if capacity <= 0:
        flash("Capacity must be a positive integer.", "error")
        return False, None

    if capacity > MAX_EVENT_CAPACITY:
        flash(f"Capacity cannot exceed {MAX_EVENT_CAPACITY}.", "error")
        return False, None

    try:
        datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        flash("Date must be in YYYY-MM-DD format.", "error")
        return False, None

    return True, capacity


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


def _parse_booking_audit_filters():
    action = request.args.get("action", "").strip().lower()
    if action not in {"", "cancel"}:
        action = ""

    actor = request.args.get("actor", "").strip().lower()
    if actor not in {"", "admin", "self_service"}:
        actor = ""

    reference_code = request.args.get("ref", "").strip().upper()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()
    where_parts = []
    params = []

    if action:
        where_parts.append("action = ?")
        params.append(action)

    if actor:
        where_parts.append("actor = ?")
        params.append(actor)

    if reference_code:
        where_parts.append("reference_code = ?")
        params.append(reference_code)

    if date_from:
        where_parts.append("DATE(created_at) >= DATE(?)")
        params.append(date_from)

    if date_to:
        where_parts.append("DATE(created_at) <= DATE(?)")
        params.append(date_to)

    where_clause = ""
    if where_parts:
        where_clause = "WHERE " + " AND ".join(where_parts)

    return {
        "action": action,
        "actor": actor,
        "reference_code": reference_code,
        "date_from": date_from,
        "date_to": date_to,
        "where_clause": where_clause,
        "params": params,
    }


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


def _is_valid_booking_name(name):
    if not name:
        flash("Your name is required.", "error")
        return False

    if len(name) > MAX_BOOKING_NAME_LENGTH:
        flash(f"Name cannot exceed {MAX_BOOKING_NAME_LENGTH} characters.", "error")
        return False

    if any(ord(ch) < 32 for ch in name):
        flash("Name contains invalid characters.", "error")
        return False

    return True


def _is_valid_reference_code(reference_code):
    if not reference_code:
        flash("Booking reference code is required.", "error")
        return False

    cleaned = reference_code.strip().upper()
    if len(cleaned) != BOOKING_REFERENCE_LENGTH:
        flash("Invalid booking reference code.", "error")
        return False

    if not all(ch in (string.ascii_uppercase + string.digits) for ch in cleaned):
        flash("Invalid booking reference code.", "error")
        return False

    return True


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
            location TEXT NOT NULL,
            capacity INTEGER NOT NULL DEFAULT 100
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            user_name TEXT NOT NULL,
            tickets INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            reference_code TEXT UNIQUE,
            FOREIGN KEY (event_id) REFERENCES events (id) ON DELETE CASCADE
        )
    """)

    _migrate_bookings_table(cursor)
    _ensure_bookings_created_at(cursor)
    _ensure_bookings_reference_code(cursor)
    _ensure_events_capacity(cursor)
    _ensure_booking_audit_table(cursor)
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
        SELECT e.id, e.name, e.date, e.location, e.capacity, COALESCE(SUM(b.tickets), 0) AS total_tickets
        FROM events e
        LEFT JOIN bookings b ON e.id = b.event_id
        GROUP BY e.id, e.name, e.date, e.location, e.capacity
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
            "capacity": row[4],
            "total_tickets": row[5],
            "remaining_tickets": max(row[4] - row[5], 0),
        }
        for row in event_rows
    ]
    return render_template("index.html", event_data=event_data)


# Add Event
@app.route("/add_event", methods=["POST"])
@admin_required
def add_event():
    name, date, location, capacity_raw = _parse_event_form()
    valid, capacity = _validate_event_fields(name, date, location, capacity_raw)
    if not valid:
        return redirect(url_for("home"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO events (name, date, location, capacity) VALUES (?, ?, ?, ?)",
        (name, date, location, capacity),
    )
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
    cursor.execute("SELECT id, name, date, location, capacity FROM events WHERE id = ?", (event_id,))
    row = cursor.fetchone()
    if row is None:
        conn.close()
        flash("Event not found.", "error")
        return redirect(url_for("home"))

    event = {"id": row[0], "name": row[1], "date": row[2], "location": row[3], "capacity": row[4]}

    if request.method == "POST":
        name, date, location, capacity_raw = _parse_event_form(default_capacity=event["capacity"])
        valid, capacity = _validate_event_fields(name, date, location, capacity_raw)
        if not valid:
            event = {
                "id": event_id,
                "name": name,
                "date": date,
                "location": location,
                "capacity": capacity_raw,
            }
            conn.close()
            return render_template("edit_event.html", event=event)

        cursor.execute(
            "UPDATE events SET name = ?, date = ?, location = ?, capacity = ? WHERE id = ?",
            (name, date, location, capacity, event_id),
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
    cursor.execute(
        """
        SELECT e.id, e.name, e.capacity, COALESCE(SUM(b.tickets), 0) AS total_tickets
        FROM events e
        LEFT JOIN bookings b ON e.id = b.event_id
        WHERE e.id = ?
        GROUP BY e.id, e.name, e.capacity
        """,
        (event_id,),
    )
    event = cursor.fetchone()
    conn.close()
    if event is None:
        flash("Event not found.", "error")
        return redirect(url_for("home"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        tickets_raw = request.form.get("tickets", "").strip()

        if not _is_valid_booking_name(name):
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
        cursor.execute("BEGIN IMMEDIATE")
        cursor.execute(
            """
            SELECT e.capacity, COALESCE(SUM(b.tickets), 0) AS total_tickets
            FROM events e
            LEFT JOIN bookings b ON e.id = b.event_id
            WHERE e.id = ?
            GROUP BY e.id, e.capacity
            """,
            (event_id,),
        )
        capacity_row = cursor.fetchone()
        if capacity_row is None:
            conn.rollback()
            conn.close()
            flash("Event not found.", "error")
            return redirect(url_for("home"))

        remaining_tickets = max(capacity_row[0] - capacity_row[1], 0)
        if remaining_tickets <= 0:
            conn.rollback()
            conn.close()
            flash("This event is sold out.", "error")
            return redirect(url_for("book_event", event_id=event_id))

        if tickets > remaining_tickets:
            conn.rollback()
            conn.close()
            flash(f"Only {remaining_tickets} tickets left for this event.", "error")
            return redirect(url_for("book_event", event_id=event_id))

        cursor.execute(
            "INSERT INTO bookings (event_id, user_name, tickets, reference_code) VALUES (?, ?, ?, ?)",
            (event_id, name, tickets, _generate_booking_reference(cursor)),
        )
        cursor.execute("SELECT reference_code FROM bookings WHERE id = last_insert_rowid()")
        booking_reference = cursor.fetchone()[0]
        conn.commit()
        conn.close()

        flash(
            f"Booking successful. Your reference code: {booking_reference}",
            "success",
        )
        return redirect(url_for("home"))

    remaining_tickets = max(event[2] - event[3], 0)
    return render_template(
        "book.html",
        event={
            "id": event[0],
            "name": event[1],
            "capacity": event[2],
            "total_tickets": event[3],
            "remaining_tickets": remaining_tickets,
        },
    )


@app.route("/my_bookings")
def my_bookings():
    reference_code = request.args.get("ref", "").strip().upper()
    booking_data = []
    has_search = bool(reference_code)

    if has_search:
        if _is_valid_reference_code(reference_code):
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT b.id, e.name, b.user_name, b.tickets, b.created_at, b.reference_code
                FROM bookings b
                JOIN events e ON e.id = b.event_id
                WHERE b.reference_code = ?
                ORDER BY b.created_at DESC, b.id DESC
                """,
                (reference_code,),
            )
            rows = cursor.fetchall()
            conn.close()
            booking_data = [
                {
                    "id": row[0],
                    "event_name": row[1],
                    "user_name": row[2],
                    "tickets": row[3],
                    "created_at": row[4],
                    "reference_code": row[5],
                }
                for row in rows
            ]
        else:
            has_search = False
            reference_code = ""

    return render_template(
        "my_bookings.html",
        booking_data=booking_data,
        reference_code=reference_code,
        has_search=has_search,
    )


@app.route("/my_bookings/cancel/<reference_code>", methods=["POST"])
def cancel_my_booking(reference_code):
    reference_code = reference_code.strip().upper()
    if not _is_valid_reference_code(reference_code):
        return redirect(url_for("my_bookings"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, reference_code FROM bookings WHERE reference_code = ?",
        (reference_code,),
    )
    row = cursor.fetchone()
    if row is None:
        conn.close()
        flash("Booking not found for this reference code.", "error")
        return redirect(url_for("my_bookings", ref=reference_code))

    cursor.execute("DELETE FROM bookings WHERE id = ?", (row[0],))
    _log_booking_audit(
        cursor=cursor,
        booking_id=row[0],
        reference_code=row[1],
        action="cancel",
        actor="self_service",
    )
    conn.commit()
    conn.close()
    flash("Your booking was cancelled.", "success")
    return redirect(url_for("my_bookings", ref=reference_code))


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
        SELECT b.id, e.name, b.user_name, b.tickets, b.created_at, b.reference_code
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
            "reference_code": row[5],
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
    cursor.execute("SELECT id, reference_code FROM bookings WHERE id = ?", (booking_id,))
    booking_row = cursor.fetchone()
    if booking_row is None:
        conn.close()
        flash("Booking not found.", "error")
        return redirect(url_for("bookings"))

    cursor.execute("DELETE FROM bookings WHERE id = ?", (booking_id,))
    _log_booking_audit(
        cursor=cursor,
        booking_id=booking_row[0],
        reference_code=booking_row[1],
        action="cancel",
        actor="admin",
    )
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
        SELECT b.id, e.name, b.user_name, b.tickets, b.created_at, b.reference_code
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
    writer.writerow(["booking_id", "event_name", "user_name", "tickets", "created_at", "reference_code"])
    writer.writerows(rows)

    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=bookings_report.csv"
    return response


@app.route("/booking_audit")
@admin_required
def booking_audit():
    filters = _parse_booking_audit_filters()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        f"""
        SELECT id, booking_id, reference_code, action, actor, created_at
        FROM booking_audit
        {filters['where_clause']}
        ORDER BY created_at DESC, id DESC
        """,
        filters["params"],
    )
    rows = cursor.fetchall()
    conn.close()

    audit_data = [
        {
            "id": row[0],
            "booking_id": row[1],
            "reference_code": row[2],
            "action": row[3],
            "actor": row[4],
            "created_at": row[5],
        }
        for row in rows
    ]

    return render_template("booking_audit.html", audit_data=audit_data, filters=filters)


@app.route("/booking_audit/export.csv")
@admin_required
def export_booking_audit_csv():
    filters = _parse_booking_audit_filters()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        f"""
        SELECT booking_id, reference_code, action, actor, created_at
        FROM booking_audit
        {filters['where_clause']}
        ORDER BY created_at DESC, id DESC
        """,
        filters["params"],
    )
    rows = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["booking_id", "reference_code", "action", "actor", "created_at"])
    writer.writerows(rows)

    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=booking_audit_report.csv"
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
