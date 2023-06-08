from flask import Blueprint

pages = Blueprint('simple_page', __name__)

from . import routes
