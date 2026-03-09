from .blueprints import register_blueprints


def register_routes(app):
    register_blueprints(app)
