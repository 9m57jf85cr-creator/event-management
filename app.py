"""Compatibility entrypoint for legacy imports and app runners."""

import smtplib

from event_management import app, create_app, init_db, main, reset_rate_limit_state
from event_management.config import load_runtime_config

# Keep a concrete reference so tests can patch `app.smtplib.SMTP`.
COMPAT_SMTP_MODULE = smtplib

__all__ = [
    "app",
    "create_app",
    "init_db",
    "load_runtime_config",
    "main",
    "reset_rate_limit_state",
    "smtplib",
]


if __name__ == "__main__":
    main()
