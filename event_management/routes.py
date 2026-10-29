"""Thin route-registration layer used by the app factory."""

from .blueprints import register_blueprints


def register_routes(app):
    """Register every blueprint in one place for a simpler startup flow."""
    register_blueprints(app)
