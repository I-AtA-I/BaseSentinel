
from flask import Blueprint

web = Blueprint(
    "web",
    __name__,
    template_folder="../templates",
    static_folder="../static",
    static_url_path="/static",
)

from basesentinel.web import routes
