
from flask import Flask
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
    app.register_blueprint(web)

    return app
