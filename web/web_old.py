from flask import Flask, render_template, redirect, url_for, request, session, jsonify
from datetime import datetime, timedelta
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy.orm import scoped_session, sessionmaker
from database import User, engine  # Import User model and engine
from sqlalchemy import select  # Required for querying the database
import base64
import requests
from flask_cors  import CORS


# Initialize Flask app
#app = Flask(__name__)
app = Flask(__name__, static_folder="templates/assets", template_folder="templates")
CORS(app,origins="*",supports_credentials=True)
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

    allowed_endpoints = ['login', 'register', 'index','req','blocked','about','reports']
    ##allowed_endpoints = ['login', 'register']
    if not session.get('user_id') and request.endpoint not in allowed_endpoints:
        return redirect(url_for('login'))




@app.route("/login", methods=["POST"])
def login():
    db = SessionLocal()
    email_or_username = request.form.get("email")
    password = request.form.get("password")

    # Query for the user
    result = db.execute(
        select(User).filter(
            (User.username == email_or_username) | (User.email == email_or_username)
        )
    )
    user = result.scalars().first()

    if user and check_password_hash(user.password, password):
        session["user_id"] = user.id
        session["username"] = user.username
        return jsonify({"message": "Login successful", "redirect": "/dashboard","user": {"username": user.username}}), 200
    else:
        return jsonify({"error": "Incorrect username or password"}), 401

@app.route("/register", methods=["POST"])
def register():
    db = SessionLocal()
    data = request.form

    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()

    # Validate input fields
    if not username or not email or not password:
        return jsonify({"message": "All fields are required"}), 400

    # Validate username for illegal characters
    if any(char in username for char in ["{", "}", "(", ")", "<", ">", "/", "\\"]):
        return jsonify({"message": "Illegal characters in username"}), 400

    # Check if the username or email already exists
    existing_user = db.execute(
        select(User).filter((User.username == username) | (User.email == email))
    ).scalars().first()

    if existing_user:
        return jsonify({"message": "Username or Email already taken"}), 400

    # Hash password before saving
    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

    # Create new user
    new_user = User(username=username, email=email, password=hashed_password)
    db.add(new_user)
    db.commit()

    return jsonify({"message": "Registration successful!"}), 201



@app.route("/logout")
def logout():
    session.pop("user_id", None)
    session.pop("username", None)
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    return render_template("index.html", username=session.get("username"))


@app.route("/blocked")
def blocked():
    r = requests.get("http://127.0.0.1:8000/get-blocked")
    return r.json()

@app.route("/requests")
def req():
    r = requests.get("http://127.0.0.1:8000/get-requests")
    return r.json()





def run_flask():
    app.run("0.0.0.0", 1234)
