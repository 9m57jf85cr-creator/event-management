from .blueprints import register_blueprints


def register_routes(app):
    """Register all HTTP routes through application blueprints."""
    register_blueprints(app)
