from flask import Flask
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_session import Session
import redis

socketio = SocketIO(cors_allowed_origins='*')
db = SQLAlchemy()
cors = CORS(supports_credentials=True)
jwt = JWTManager()
ServerSession = Session()


def create_app(debug=False):
    app = Flask(__name__)
    app.secret_key = 'hjgjhghghj'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:123321@localhost:5432/cabinet'
    app.config['JWT_SECRET_KEY'] = 'super-secret'
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_PERMANENT'] = False
    app.config['SESSION_USE_SIGNER'] = True
    app.config['SESSION_REDIS'] = redis.from_url('redis://127.0.0.1:6379')

    from .main import pages as pages_blueprint
    app.register_blueprint(pages_blueprint)

    ServerSession.init_app(app)
    jwt.init_app(app)
    cors.init_app(app)
    db.init_app(app)
    socketio.init_app(app)
    return app
