import sqlite3
import time

from flask import request


def get_client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


def reset_rate_limit_state(app, get_db_connection):
    conn = get_db_connection(app)
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM request_rate_limit")
    except sqlite3.OperationalError:
        conn.close()
        return
    conn.commit()
    conn.close()


def check_rate_limit(app, scope, get_db_connection):
    limit_mapping = {
        "login": app.config["RATE_LIMIT_LOGIN_MAX_REQUESTS"],
        "booking": app.config["RATE_LIMIT_BOOKING_MAX_REQUESTS"],
    }
    max_requests = limit_mapping[scope]
    window_seconds = app.config["RATE_LIMIT_WINDOW_SECONDS"]
    now = int(time.time())
    client_ip = get_client_ip()
    bucket_start = now - (now % window_seconds)
    cutoff = now - (window_seconds * 10)

    conn = get_db_connection(app)
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
