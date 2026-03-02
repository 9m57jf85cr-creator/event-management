from .api import bp as api_bp
from .auth import bp as auth_bp
from .bookings import bp as bookings_bp
from .events import bp as events_bp


def register_blueprints(app):
    app.register_blueprint(auth_bp)
    app.register_blueprint(events_bp)
    app.register_blueprint(bookings_bp)
    app.register_blueprint(api_bp)
