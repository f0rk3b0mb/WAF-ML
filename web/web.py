from flask import Flask, render_template, redirect, url_for, request, session
from datetime import datetime, timedelta
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy.orm import scoped_session, sessionmaker
from database import User, engine  # Ensure User model is imported correctly
import base64

# Initialize Flask app
app = Flask(__name__)
app.secret_key = "jdfkfkkigkjgjkjg"
app.permanent_session_lifetime = timedelta(minutes=5)

def b64encode_img(img):
    return base64.b64encode(img.getvalue()).decode('utf-8')

app.add_template_filter(b64encode_img, 'b64encode')

# Database session management (Sync Session)
SessionLocal = scoped_session(sessionmaker(bind=engine))

# Function to get DB session (sync version)
async def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        await db.close()

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
    db = next(get_db())  # Use database session
    if request.method == "POST":
        email_or_username = request.form.get("email")
        password = request.form.get("password")

        # Check if user exists by email or username
        user = db.query(User).filter((User.username == email_or_username) | (User.email == email_or_username)).first()

        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            session["username"] = user.username
            return redirect(url_for("dashboard"))
        else:
            return render_template("login.html", message="Incorrect username or password")

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    db = next(get_db())  # Use database session
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        # Validate username for illegal characters
        if any(char in username for char in ["{", "}", "(", ")", "<", ">", "/", "\\"]):
            return render_template("register.html", message="Illegal characters in username")

        # Check if the email already exists
        existing_user = db.query(User).filter_by(email=email).first()
        if existing_user:
            return render_template("register.html", message="Email already taken.")

        # Hash password and add user to the database
        hashed_password = generate_password_hash(password)
        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            date_registered=datetime.utcnow()
        )
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

def run_flask():
    app.run("0.0.0.0",1234)