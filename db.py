# python code to create tables in sqlite using sqlalchemy


from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime


db = SQLAlchemy()
bcrypt = Bcrypt()

# define the location of the database file

DATABASE_URL = "sqlite:///./instance/requests.db"


class Request(db.Model):

    id = db.Column(db.Integer, primary_key=True, index=True)
    url = db.Column(db.String, index=True)
    method = db.Column(db.String)
    ip_address = db.Column(db.String, nullable=True, index=True)
    headers = db.Column(db.String)
    body = db.Column(db.String)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Define the Blocked model to store blocked IPs
class Blocked(db.Model):

    id = db.Column(db.Integer, primary_key=True, index=True)
    ip_address = db.Column(db.String, nullable=True, index=True)
    url = db.Column(db.String, nullable=True, index=True)
    reason = db.Column(db.String, nullable=True)  # Reason for blocking
    blocked_at = db.Column(db.DateTime, default=lambda: datetime.now(datetime.timezone.utc))
    status = db.Column(db.String, default="blocked")

# Define the User model with only username, email, and password
class User(db.Model):

    id = db.Column(db.Integer, primary_key=True, index=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)