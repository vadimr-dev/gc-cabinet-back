from .. import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    auth_key = db.Column(db.String(50))


class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    two_factor_auth = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref=db.backref('accounts', lazy=True))
    name = db.Column(db.String(50))
    surname = db.Column(db.String(50))
    info = db.Column(db.Text)
    photo = db.Column(db.Text)


class Events(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    title = db.Column(db.String(50), nullable=False)
    start_event = db.Column(db.TIMESTAMP, nullable=False)
    end_event = db.Column(db.TIMESTAMP, nullable=False)
