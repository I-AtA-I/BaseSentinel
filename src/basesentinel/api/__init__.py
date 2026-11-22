from flask import Blueprint

api = Blueprint("api", __name__)

from basesentinel.api import routes
from basesentinel.api import operations
from basesentinel.api import detection_rules
