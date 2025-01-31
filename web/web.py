from flask import Flask, render_template, redirect, url_for, request, session
from datetime import datetime, timedelta
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy.orm import scoped_session, sessionmaker
from database import User, engine  # Import User model and engine
from sqlalchemy import select  # Required for querying the database
import base64
import requests


# Initialize Flask app
app = Flask(__name__)
app.secret_key = "jdfkfkkigkjgjkjg"
app.permanent_session_lifetime = timedelta(minutes=5)

# Function to encode image as base64
def b64encode_img(img):
    return base64.b64encode(img.getvalue()).decode('utf-8')

# Add b64encode_img as a template filter
app.add_template_filter(b64encode_img, 'b64encode')

# Database session management (Sync Session)
SessionLocal = scoped_session(sessionmaker(bind=engine))

# Function to get DB session (sync version)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.before_request
def before_request():
    """Ensure session validity before processing a request."""
    if 'user_id' in session and session.permanent:
        session.modified = True

    allowed_endpoints = ['login', 'register', 'index']
    if not session.get('user_id') and request.endpoint not in allowed_endpoints:
        return redirect(url_for('login'))

@app.route("/")
def index():
    return render_template("landing.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    # Sync DB query using SessionLocal
    db = SessionLocal()
    if request.method == "POST":
        email_or_username = request.form.get("email")
        password = request.form.get("password")

        # Query for the user (sync)
        result = db.execute(
            select(User).filter(
                (User.username == email_or_username) | (User.email == email_or_username)
            )
        )
        user = result.scalars().first()

        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            session["username"] = user.username
            return redirect(url_for("dashboard"))
        else:
            return render_template("login.html", message="Incorrect username or password")

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    db = SessionLocal()
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        # Validate username for illegal characters
        if any(char in username for char in ["{", "}", "(", ")", "<", ">", "/", "\\"]):
            return render_template("register.html", message="Illegal characters in username")

        # Check if the email already exists
        result = db.execute(select(User).filter_by(email=email))
        existing_user = result.scalars().first()
        if existing_user:
            return render_template("register.html", message="Email already taken.")

        # Hash password and add user to the database
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        db.add(new_user)
        db.commit()

        return redirect(url_for("login", message="Registration successful! Awaiting admin approval."))

    return render_template("register.html")

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    session.pop("username", None)
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session.get("username"))


@app.route("/blocked")
def b():
    r = requests.get("http://127.0.0.1:8000/get-blocked")
    return r.json()

@app.route("/requests")
def r():
    r = requests.get("http://127.0.0.1:8000/get-requests")
    return r.json()


def run_flask():
    app.run("0.0.0.0", 1234)
