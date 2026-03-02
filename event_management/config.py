import os

from .constants import DEFAULT_SECRET_KEY

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin123"
DEFAULT_API_KEY = "dev-api-key-change-me"


def load_dotenv(path=".env"):
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


def is_production_environment():
    return os.getenv("FLASK_ENV", "development").strip().lower() == "production"


def resolve_database_path(database_value):
    database_path = database_value.strip() or "events.db"
    if os.path.isabs(database_path):
        return database_path
    return os.path.join(PROJECT_ROOT, database_path)


def env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_runtime_config():
    is_production = is_production_environment()
    secret_key = os.getenv("SECRET_KEY", DEFAULT_SECRET_KEY)
    admin_username = os.getenv("ADMIN_USERNAME", DEFAULT_ADMIN_USERNAME).strip()
    admin_password = os.getenv("ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD)
    api_key = os.getenv("API_KEY", DEFAULT_API_KEY)
    database = resolve_database_path(os.getenv("DATABASE", "events.db"))
    rate_limit_window_seconds = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
    rate_limit_login_max_requests = int(os.getenv("RATE_LIMIT_LOGIN_MAX_REQUESTS", "10"))
    rate_limit_booking_max_requests = int(os.getenv("RATE_LIMIT_BOOKING_MAX_REQUESTS", "30"))
    smtp_enabled = env_bool("SMTP_ENABLED", False)
    smtp_host = os.getenv("SMTP_HOST", "").strip()
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_username = os.getenv("SMTP_USERNAME", "").strip()
    smtp_password = os.getenv("SMTP_PASSWORD", "")
    smtp_use_tls = env_bool("SMTP_USE_TLS", True)
    smtp_from_email = os.getenv("SMTP_FROM_EMAIL", "no-reply@localhost").strip()

    if not admin_username or not admin_password:
        raise RuntimeError("ADMIN_USERNAME and ADMIN_PASSWORD must be set.")

    if is_production and secret_key == DEFAULT_SECRET_KEY:
        raise RuntimeError("SECRET_KEY must be changed in production.")
    if is_production and admin_username == DEFAULT_ADMIN_USERNAME:
        raise RuntimeError("ADMIN_USERNAME must be changed in production.")
    if is_production and admin_password == DEFAULT_ADMIN_PASSWORD:
        raise RuntimeError("ADMIN_PASSWORD must be changed in production.")
    if is_production and api_key == DEFAULT_API_KEY:
        raise RuntimeError("API_KEY must be changed in production.")

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
