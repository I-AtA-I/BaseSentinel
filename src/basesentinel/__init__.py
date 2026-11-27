
from flask import Flask, redirect, render_template, request
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import MetaData

from basesentinel.config import Config


NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

db = SQLAlchemy(
    metadata=MetaData(naming_convention=NAMING_CONVENTION)
)

migrate = Migrate()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)

    import basesentinel.models

    migrate.init_app(app, db)

    from basesentinel.api import api
    from basesentinel.web import web

    app.register_blueprint(api, url_prefix="/api/v1")
    app.register_blueprint(web, url_prefix="/app")

    @app.get("/")
    def public_home():
        return render_template("public.html")

    @app.get("/app")
    def app_entry():
        return redirect("/app/", code=308)

    @app.before_request
    def redirect_legacy_web_paths():
        path = request.path
        legacy_prefixes = (
            "/static", "/login", "/logout", "/events", "/activities",
            "/alerts", "/detection-rules", "/reports", "/settings",
            "/agent-health", "/agents", "/agent-invite",
        )
        if path == "/app" or path.startswith("/app/") or path == "/":
            return None
        if path == "/api" or path.startswith("/api/"):
            return None
        if any(path == prefix or path.startswith(prefix + "/") for prefix in legacy_prefixes):
            return redirect(f"/app{request.full_path}".rstrip("?"), code=308)
        return None

    return app
