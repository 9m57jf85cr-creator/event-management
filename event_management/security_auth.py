import secrets
from functools import wraps

from flask import flash, redirect, request, session, url_for


def admin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            flash("Admin login required.", "error")
            return redirect(url_for("auth.login", next=request.path))
        return view_func(*args, **kwargs)

    return wrapper


def is_safe_next_url(next_url):
    return next_url.startswith("/") and not next_url.startswith("//")


def credentials_match(app, username, password):
    expected_username = app.config["ADMIN_USERNAME"]
    expected_password = app.config["ADMIN_PASSWORD"]
    return (
        secrets.compare_digest(username.encode("utf-8"), expected_username.encode("utf-8"))
        and secrets.compare_digest(password.encode("utf-8"), expected_password.encode("utf-8"))
    )


def api_key_is_valid(app):
    expected_key = app.config["API_KEY"]
    received_key = request.headers.get("X-API-Key", "")
    return secrets.compare_digest(received_key.encode("utf-8"), expected_key.encode("utf-8"))
