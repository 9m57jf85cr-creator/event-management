import os
from datetime import timedelta

from flask import Flask

from .config import PROJECT_ROOT, load_dotenv, load_runtime_config
from .date_utils import format_event_date
from .db import get_db_connection, init_db as init_db_impl
from .migrations import apply_pending_migrations
from .routes import register_routes
from .security import (
    api_key_is_valid,
    check_rate_limit,
    register_security_hooks,
    reset_rate_limit_state as reset_rl_impl,
)


load_dotenv()


def _configure_app(flask_app):
    flask_app.config.update(load_runtime_config())
    flask_app.config["SESSION_COOKIE_HTTPONLY"] = True
    flask_app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    flask_app.config["SESSION_COOKIE_SECURE"] = flask_app.config["IS_PRODUCTION"]
    flask_app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)
    flask_app.jinja_env.filters["format_event_date"] = format_event_date

    register_security_hooks(
        flask_app,
        check_rate_limit_func=lambda scope: check_rate_limit(flask_app, scope, get_db_connection),
        api_key_validator=lambda: api_key_is_valid(flask_app),
    )
    register_routes(flask_app)


def register_cli_commands(flask_app):
    if getattr(flask_app, "_event_mgmt_cli_registered", False):
        return

    @flask_app.cli.command("db-upgrade")
    def db_upgrade():
        apply_pending_migrations(flask_app, get_db_connection)
        init_db_impl(flask_app)
        print("Database migrations applied.")

    flask_app._event_mgmt_cli_registered = True


def create_app(init_database=True):
    flask_app = Flask(
        __name__,
        template_folder=os.path.join(PROJECT_ROOT, "templates"),
        static_folder=os.path.join(PROJECT_ROOT, "static"),
    )

    _configure_app(flask_app)
    register_cli_commands(flask_app)

    if init_database:
        apply_pending_migrations(flask_app, get_db_connection)
        init_db_impl(flask_app)

    return flask_app


# Backward-compatible global app object for existing imports/tests.
app = create_app(init_database=True)


def init_db():
    apply_pending_migrations(app, get_db_connection)
    init_db_impl(app)


def reset_rate_limit_state():
    reset_rl_impl(app, get_db_connection)


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
