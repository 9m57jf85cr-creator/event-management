import secrets

from flask import abort, request, session


def generate_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def register_security_hooks(app, check_rate_limit_func, api_key_validator):
    @app.context_processor
    def inject_csrf_token():
        return {"csrf_token": generate_csrf_token}

    @app.before_request
    def protect_from_csrf():
        if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return
        if request.path.startswith("/api/"):
            return

        expected = session.get("_csrf_token", "")
        received = request.form.get("csrf_token", "")
        if not expected or not received or not secrets.compare_digest(expected, received):
            abort(400, description="Invalid CSRF token.")

    @app.before_request
    def enforce_rate_limits():
        if request.method != "POST":
            return

        endpoint = request.endpoint or ""
        if endpoint in {"login", "auth.login"}:
            if not check_rate_limit_func("login"):
                abort(429, description="Too many login attempts. Please try again later.")
            return

        if endpoint in {"book_event", "events.book_event"}:
            if not check_rate_limit_func("booking"):
                abort(429, description="Too many booking attempts. Please try again later.")

    @app.before_request
    def enforce_api_key_auth():
        if not request.path.startswith("/api/"):
            return

        if not api_key_validator():
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
