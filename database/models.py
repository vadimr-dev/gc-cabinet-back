from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, Boolean, \
    String, Text, TIMESTAMP, ForeignKey

Base = declarative_base()


class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    password = Column(String(120), nullable=False)
    auth_key = Column(String(50))


class Account(Base):
    __tablename__ = 'accounts'
    
    id = Column(Integer, primary_key=True)
    two_factor_auth = Column(Boolean, default=False)
    user_id = Column(Integer, ForeignKey('users.id'))
    user = relationship('User', backref=backref('accounts', lazy=True))
    name = Column(String(50))
    surname = Column(String(50))
    photo = Column(Text)


class Events(Base):
    __tablename__ = 'events'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False)
    title = Column(String(50), nullable=False)
    date = Column(TIMESTAMP, nullable=False)
    start_event = Column(String(5), nullable=False)
    end_event = Column(String(5), nullable=False)
