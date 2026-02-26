from flask import Flask, abort, flash, jsonify, make_response, redirect, render_template, request, session, url_for
from datetime import datetime
from datetime import timedelta
from functools import wraps
import csv
from email.message import EmailMessage
import io
import os
import re
import secrets
import smtplib
import sqlite3
import string
import time

DEFAULT_SECRET_KEY = "dev-secret-key-change-me"
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
MAX_EVENT_NAME_LENGTH = 120
MAX_LOCATION_LENGTH = 120
MAX_BOOKING_NAME_LENGTH = 80
MAX_BOOKING_EMAIL_LENGTH = 254
MAX_BOOKING_PHONE_LENGTH = 20
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


def _env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_runtime_config():
    is_production = _is_production_environment()
    secret_key = os.getenv("SECRET_KEY", DEFAULT_SECRET_KEY)
    admin_username = os.getenv("ADMIN_USERNAME", "admin").strip()
    admin_password = os.getenv("ADMIN_PASSWORD", "admin123")
    api_key = os.getenv("API_KEY", "dev-api-key-change-me")
    database = _resolve_database_path(os.getenv("DATABASE", "events.db"))
    rate_limit_window_seconds = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
    rate_limit_login_max_requests = int(os.getenv("RATE_LIMIT_LOGIN_MAX_REQUESTS", "10"))
    rate_limit_booking_max_requests = int(os.getenv("RATE_LIMIT_BOOKING_MAX_REQUESTS", "30"))
    smtp_enabled = _env_bool("SMTP_ENABLED", False)
    smtp_host = os.getenv("SMTP_HOST", "").strip()
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_username = os.getenv("SMTP_USERNAME", "").strip()
    smtp_password = os.getenv("SMTP_PASSWORD", "")
    smtp_use_tls = _env_bool("SMTP_USE_TLS", True)
    smtp_from_email = os.getenv("SMTP_FROM_EMAIL", "no-reply@localhost").strip()

    if not admin_username or not admin_password:
        raise RuntimeError("ADMIN_USERNAME and ADMIN_PASSWORD must be set.")

    if is_production and secret_key == DEFAULT_SECRET_KEY:
        raise RuntimeError("SECRET_KEY must be changed in production.")

    if not api_key:
        raise RuntimeError("API_KEY must be set.")

    if rate_limit_window_seconds <= 0:
        raise RuntimeError("RATE_LIMIT_WINDOW_SECONDS must be > 0.")

    if rate_limit_login_max_requests <= 0 or rate_limit_booking_max_requests <= 0:
        raise RuntimeError("Rate limit max request values must be > 0.")

    if smtp_enabled and not smtp_host:
        raise RuntimeError("SMTP_HOST must be set when SMTP_ENABLED is true.")

    if smtp_port <= 0:
        raise RuntimeError("SMTP_PORT must be > 0.")

    if smtp_enabled and not smtp_from_email:
        raise RuntimeError("SMTP_FROM_EMAIL must be set when SMTP_ENABLED is true.")

    return {
        "SECRET_KEY": secret_key,
        "DATABASE": database,
        "ADMIN_USERNAME": admin_username,
        "ADMIN_PASSWORD": admin_password,
        "API_KEY": api_key,
        "IS_PRODUCTION": is_production,
        "RATE_LIMIT_WINDOW_SECONDS": rate_limit_window_seconds,
        "RATE_LIMIT_LOGIN_MAX_REQUESTS": rate_limit_login_max_requests,
        "RATE_LIMIT_BOOKING_MAX_REQUESTS": rate_limit_booking_max_requests,
        "SMTP_ENABLED": smtp_enabled,
        "SMTP_HOST": smtp_host,
        "SMTP_PORT": smtp_port,
        "SMTP_USERNAME": smtp_username,
        "SMTP_PASSWORD": smtp_password,
        "SMTP_USE_TLS": smtp_use_tls,
        "SMTP_FROM_EMAIL": smtp_from_email,
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
            user_email TEXT NOT NULL DEFAULT '',
            user_phone TEXT NOT NULL DEFAULT '',
            confirmation_email_status TEXT NOT NULL DEFAULT 'skipped',
            confirmation_email_error TEXT NOT NULL DEFAULT '',
            tickets INTEGER NOT NULL,
            FOREIGN KEY (event_id) REFERENCES events (id) ON DELETE CASCADE
        )
    """)
    cursor.execute("""
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


def _ensure_bookings_contact_fields(cursor):
    cursor.execute("PRAGMA table_info(bookings)")
    columns = {row[1] for row in cursor.fetchall()}
    if "user_email" not in columns:
        cursor.execute("ALTER TABLE bookings ADD COLUMN user_email TEXT NOT NULL DEFAULT ''")
    if "user_phone" not in columns:
        cursor.execute("ALTER TABLE bookings ADD COLUMN user_phone TEXT NOT NULL DEFAULT ''")


def _ensure_bookings_email_status_fields(cursor):
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


def _ensure_request_rate_limit_table(cursor):
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
    if action not in {"", "cancel", "create"}:
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


def _parse_events_api_filters():
    query = request.args.get("q", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to = request.args.get("date_to", "").strip()

    for value in (date_from, date_to):
        if value:
            try:
                datetime.strptime(value, "%Y-%m-%d")
            except ValueError:
                abort(400, description="date_from/date_to must be in YYYY-MM-DD format.")

    page = request.args.get("page", default=1, type=int)
    per_page = request.args.get("per_page", default=20, type=int)
    if page < 1:
        page = 1
    if per_page < 1:
        per_page = 1
    per_page = min(per_page, 100)

    where_parts = []
    params = []
    if query:
        where_parts.append("(e.name LIKE ? OR e.location LIKE ?)")
        pattern = f"%{query}%"
        params.extend([pattern, pattern])

    if date_from:
        where_parts.append("e.date >= ?")
        params.append(date_from)

    if date_to:
        where_parts.append("e.date <= ?")
        params.append(date_to)

    where_clause = ""
    if where_parts:
        where_clause = "WHERE " + " AND ".join(where_parts)

    return {
        "query": query,
        "date_from": date_from,
        "date_to": date_to,
        "page": page,
        "per_page": per_page,
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


def _is_valid_booking_email(email):
    if not email:
        flash("Email is required.", "error")
        return False

    if len(email) > MAX_BOOKING_EMAIL_LENGTH:
        flash(f"Email cannot exceed {MAX_BOOKING_EMAIL_LENGTH} characters.", "error")
        return False

    if any(ord(ch) < 32 for ch in email):
        flash("Email contains invalid characters.", "error")
        return False

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        flash("Enter a valid email address.", "error")
        return False

    return True


def _is_valid_booking_phone(phone):
    if not phone:
        flash("Phone number is required.", "error")
        return False

    if len(phone) > MAX_BOOKING_PHONE_LENGTH:
        flash(f"Phone number cannot exceed {MAX_BOOKING_PHONE_LENGTH} characters.", "error")
        return False

    if any(ord(ch) < 32 for ch in phone):
        flash("Phone number contains invalid characters.", "error")
        return False

    if not re.fullmatch(r"[0-9+\-\s()]+", phone):
        flash("Enter a valid phone number.", "error")
        return False

    digit_count = sum(ch.isdigit() for ch in phone)
    if digit_count < 7:
        flash("Enter a valid phone number.", "error")
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


def _send_notification_email(to_email, subject, body_lines):
    if not app.config.get("SMTP_ENABLED"):
        return "skipped", "SMTP is disabled."

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = app.config["SMTP_FROM_EMAIL"]
    message["To"] = to_email
    message.set_content("\n".join(body_lines))

    try:
        with smtplib.SMTP(
            app.config["SMTP_HOST"],
            app.config["SMTP_PORT"],
            timeout=10,
        ) as smtp_client:
            if app.config["SMTP_USE_TLS"]:
                smtp_client.starttls()

            if app.config["SMTP_USERNAME"] or app.config["SMTP_PASSWORD"]:
                smtp_client.login(
                    app.config["SMTP_USERNAME"],
                    app.config["SMTP_PASSWORD"],
                )

            smtp_client.send_message(message)
            return "sent", ""
    except Exception as exc:
        app.logger.exception("Failed to send notification email.")
        return "failed", str(exc)[:300]


def _send_booking_confirmation_email(to_email, user_name, event_name, event_date, event_location, tickets, reference_code):
    return _send_notification_email(
        to_email=to_email,
        subject=f"Booking Confirmed: {event_name}",
        body_lines=[
            f"Hi {user_name},",
            "",
            "Your booking is confirmed.",
            f"Event: {event_name}",
            f"Date: {event_date}",
            f"Location: {event_location}",
            f"Tickets: {tickets}",
            f"Reference Code: {reference_code}",
            "",
            "Thank you.",
        ],
    )


def _send_booking_cancellation_email(to_email, user_name, event_name, reference_code):
    return _send_notification_email(
        to_email=to_email,
        subject=f"Booking Cancelled: {event_name}",
        body_lines=[
            f"Hi {user_name},",
            "",
            "Your booking has been cancelled.",
            f"Event: {event_name}",
            f"Reference Code: {reference_code}",
        ],
    )


def _update_booking_confirmation_email_status(booking_id, status, error_message):
    conn = get_db_connection()
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


def _get_client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _api_key_is_valid():
    expected_key = app.config["API_KEY"]
    received_key = request.headers.get("X-API-Key", "")
    return secrets.compare_digest(received_key.encode("utf-8"), expected_key.encode("utf-8"))


def reset_rate_limit_state():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM request_rate_limit")
    except sqlite3.OperationalError:
        conn.close()
        return
    conn.commit()
    conn.close()


def _check_rate_limit(scope):
    limit_mapping = {
        "login": app.config["RATE_LIMIT_LOGIN_MAX_REQUESTS"],
        "booking": app.config["RATE_LIMIT_BOOKING_MAX_REQUESTS"],
    }
    max_requests = limit_mapping[scope]
    window_seconds = app.config["RATE_LIMIT_WINDOW_SECONDS"]
    now = int(time.time())
    client_ip = _get_client_ip()
    bucket_start = now - (now % window_seconds)
    cutoff = now - (window_seconds * 10)

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("BEGIN IMMEDIATE")
        cursor.execute(
            "DELETE FROM request_rate_limit WHERE scope = ? AND client_ip = ? AND bucket_start < ?",
            (scope, client_ip, cutoff),
        )
        cursor.execute(
            """
            INSERT INTO request_rate_limit (scope, client_ip, bucket_start, request_count)
            VALUES (?, ?, ?, 1)
            ON CONFLICT(scope, client_ip, bucket_start)
            DO UPDATE SET request_count = request_count + 1
            """,
            (scope, client_ip, bucket_start),
        )
        cursor.execute(
            """
            SELECT request_count
            FROM request_rate_limit
            WHERE scope = ? AND client_ip = ? AND bucket_start = ?
            """,
            (scope, client_ip, bucket_start),
        )
        request_count = cursor.fetchone()[0]
        conn.commit()
        return request_count <= max_requests
    finally:
        conn.close()


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


@app.before_request
def enforce_rate_limits():
    if request.method != "POST":
        return

    if request.endpoint == "login":
        if not _check_rate_limit("login"):
            abort(429, description="Too many login attempts. Please try again later.")
        return

    if request.endpoint == "book_event":
        if not _check_rate_limit("booking"):
            abort(429, description="Too many booking attempts. Please try again later.")


@app.before_request
def enforce_api_key_auth():
    if not request.path.startswith("/api/"):
        return

    if not _api_key_is_valid():
        abort(401, description="Invalid or missing API key.")


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
            user_email TEXT NOT NULL DEFAULT '',
            user_phone TEXT NOT NULL DEFAULT '',
            confirmation_email_status TEXT NOT NULL DEFAULT 'skipped',
            confirmation_email_error TEXT NOT NULL DEFAULT '',
            tickets INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            reference_code TEXT UNIQUE,
            FOREIGN KEY (event_id) REFERENCES events (id) ON DELETE CASCADE
        )
    """)

    _migrate_bookings_table(cursor)
    _ensure_bookings_created_at(cursor)
    _ensure_bookings_reference_code(cursor)
    _ensure_bookings_contact_fields(cursor)
    _ensure_bookings_email_status_fields(cursor)
    _ensure_events_capacity(cursor)
    _ensure_booking_audit_table(cursor)
    _ensure_request_rate_limit_table(cursor)
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


def _events_api_response():
    filters = _parse_events_api_filters()
    page = filters["page"]
    per_page = filters["per_page"]

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        f"""
        SELECT COUNT(*)
        FROM events e
        {filters['where_clause']}
        """,
        filters["params"],
    )
    total_items = cursor.fetchone()[0]
    total_pages = max(1, (total_items + per_page - 1) // per_page)
    if page > total_pages:
        page = total_pages
    offset = (page - 1) * per_page

    cursor.execute(
        f"""
        SELECT e.id, e.name, e.date, e.location, e.capacity, COALESCE(SUM(b.tickets), 0) AS total_tickets
        FROM events e
        LEFT JOIN bookings b ON e.id = b.event_id
        {filters['where_clause']}
        GROUP BY e.id, e.name, e.date, e.location, e.capacity
        ORDER BY e.date, e.id
        LIMIT ? OFFSET ?
        """,
        filters["params"] + [per_page, offset],
    )
    rows = cursor.fetchall()
    conn.close()

    items = []
    for row in rows:
        remaining_tickets = max(row[4] - row[5], 0)
        items.append(
            {
                "id": row[0],
                "name": row[1],
                "date": row[2],
                "location": row[3],
                "capacity": row[4],
                "total_tickets": row[5],
                "remaining_tickets": remaining_tickets,
                "is_sold_out": remaining_tickets == 0,
            }
        )

    return jsonify(
        {
            "items": items,
            "page": page,
            "per_page": per_page,
            "total_items": total_items,
            "total_pages": total_pages,
        }
    )


@app.route("/api/events")
@app.route("/api/v1/events")
def api_events():
    return _events_api_response()


@app.route("/api/v1/health")
def api_health_v1():
    return jsonify({"status": "ok", "version": "v1"})


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
        SELECT e.id, e.name, e.date, e.location, e.capacity, COALESCE(SUM(b.tickets), 0) AS total_tickets
        FROM events e
        LEFT JOIN bookings b ON e.id = b.event_id
        WHERE e.id = ?
        GROUP BY e.id, e.name, e.date, e.location, e.capacity
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
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        tickets_raw = request.form.get("tickets", "").strip()
        event_name = event[1]

        if not _is_valid_booking_name(name):
            return redirect(url_for("book_event", event_id=event_id))

        if not _is_valid_booking_email(email):
            return redirect(url_for("book_event", event_id=event_id))

        if not _is_valid_booking_phone(phone):
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
                name,
                email,
                phone,
                "pending",
                "",
                tickets,
                _generate_booking_reference(cursor),
            ),
        )
        booking_id = cursor.lastrowid
        cursor.execute("SELECT reference_code FROM bookings WHERE id = ?", (booking_id,))
        booking_reference = cursor.fetchone()[0]
        _log_booking_audit(
            cursor=cursor,
            booking_id=booking_id,
            reference_code=booking_reference,
            action="create",
            actor="self_service",
        )
        conn.commit()
        conn.close()
        email_status, email_error = _send_booking_confirmation_email(
            to_email=email,
            user_name=name,
            event_name=event_name,
            event_date=event[2],
            event_location=event[3],
            tickets=tickets,
            reference_code=booking_reference,
        )
        _update_booking_confirmation_email_status(booking_id, email_status, email_error)

        flash(
            f"Booking successful. Your reference code: {booking_reference}",
            "success",
        )
        return redirect(url_for("home"))

    remaining_tickets = max(event[4] - event[5], 0)
    return render_template(
        "book.html",
        event={
            "id": event[0],
            "name": event[1],
            "capacity": event[4],
            "total_tickets": event[5],
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
                SELECT b.id, e.name, b.user_name, b.user_email, b.user_phone, b.tickets, b.created_at, b.reference_code
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
                    "user_email": row[3],
                    "user_phone": row[4],
                    "tickets": row[5],
                    "created_at": row[6],
                    "reference_code": row[7],
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
        """
        SELECT b.id, b.reference_code, b.user_name, b.user_email, e.name
        FROM bookings b
        JOIN events e ON e.id = b.event_id
        WHERE b.reference_code = ?
        """,
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
    _send_booking_cancellation_email(
        to_email=row[3],
        user_name=row[2],
        event_name=row[4],
        reference_code=row[1],
    )
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
        where_clause = "WHERE e.name LIKE ? OR b.user_name LIKE ? OR b.user_email LIKE ? OR b.user_phone LIKE ?"
        pattern = f"%{query}%"
        params = [pattern, pattern, pattern, pattern]

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
        SELECT
            b.id,
            e.name,
            b.user_name,
            b.user_email,
            b.user_phone,
            b.confirmation_email_status,
            b.confirmation_email_error,
            b.tickets,
            b.created_at,
            b.reference_code
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
            "user_email": row[3],
            "user_phone": row[4],
            "confirmation_email_status": row[5],
            "confirmation_email_error": row[6],
            "tickets": row[7],
            "created_at": row[8],
            "reference_code": row[9],
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
    cursor.execute(
        """
        SELECT b.id, b.reference_code, b.user_name, b.user_email, e.name
        FROM bookings b
        JOIN events e ON e.id = b.event_id
        WHERE b.id = ?
        """,
        (booking_id,),
    )
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
    _send_booking_cancellation_email(
        to_email=booking_row[3],
        user_name=booking_row[2],
        event_name=booking_row[4],
        reference_code=booking_row[1],
    )
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
        where_clause = "WHERE e.name LIKE ? OR b.user_name LIKE ? OR b.user_email LIKE ? OR b.user_phone LIKE ?"
        pattern = f"%{query}%"
        params = [pattern, pattern, pattern, pattern]

    cursor.execute(
        f"""
        SELECT b.id, e.name, b.user_name, b.user_email, b.user_phone, b.tickets, b.created_at, b.reference_code
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
    writer.writerow(
        [
            "booking_id",
            "event_name",
            "user_name",
            "user_email",
            "user_phone",
            "tickets",
            "created_at",
            "reference_code",
        ]
    )
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

    app.run(debug=debug, host=host, port=port, use_reloader=False)


if __name__ == "__main__":
    main()
