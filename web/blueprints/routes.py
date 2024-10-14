# routes.py
from flask import Blueprint, render_template, redirect, url_for, request, session, send_file
from utils import login_required, admin_required
import datetime
from data_fetch import (
    get_blocked_requests,
    get_recent_attacks,
    get_top_malicious_urls,
    get_total_requests
)
from database import get_db, User  # Import your models and get_db
from sqlalchemy.orm import Session  # Import Session for typing
from werkzeug.security import check_password_hash, generate_password_hash
from visualizations import visualize_blocked_ips, visualize_logs


web = Blueprint('web', __name__)

@web.route("/")
def index():
    return render_template("landing.html")

@web.before_request
def before_request():
    if 'user_id' in session and session.permanent:
        session.modified = True  # Reset the session timer on each request

    allowed_endpoints = ['web.login', 'web.register', 'web.index', 'web.faq']
    if not session.get('user_id') and request.endpoint not in allowed_endpoints:
        return redirect(url_for('web.login'))

@web.route("/login", methods=["GET", "POST"])
def login():
    db: Session = next(get_db())  # Get a new database session
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        
        user = db.query(User).filter((User.username == email) | (User.email == email)).first()

        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            session["username"] = user.username
            return redirect(url_for("web.dashboard"))
        else:
            return render_template("login.html", message="Incorrect username or password")

    return render_template("login.html")

@web.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    db: Session = next(get_db())  # Get a new database session
    if request.method == "POST":
        entered_otp = request.form.get("otp")  # Get the OTP entered by the user

        user = db.query(User).get(session.get('user_id'))

        if user and int(entered_otp) == user.otp:
            return redirect(url_for("web.dashboard"))
        else:
            return render_template("verify_otp.html", message="Incorrect OTP. Please try again.")

    return render_template("verify_otp.html")

@web.route("/register", methods=["GET", "POST"])
def register():
    db: Session = next(get_db())  # Get a new database session
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")

        if any(char in username for char in ["{", "}", "(", ")", "<", ">", "/", "\\"]):
            return render_template("register.html", message="Illegal characters in username")

        existing_user = db.query(User).filter_by(email=email).first()
        if existing_user:
            return render_template("register.html", message="Email already taken.")

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, email=email, date_registered=datetime.date.today())
        db.add(new_user)
        db.commit()
        return render_template("login.html", message="Awaiting admin approval.")

    return render_template("register.html")

@web.route('/dashboard')
@login_required
def dashboard():
    db: Session = next(get_db())  # Get a new database session
    total_requests = get_total_requests()  # Fetch from logs or DB
    blocked_requests = get_blocked_requests()  # Fetch from logs or DB
    top_malicious_urls = get_top_malicious_urls()  # Most frequent URLs
    recent_attacks = get_recent_attacks()  # Recent attack details

    return render_template('dashboard.html', 
                           total_requests=total_requests, 
                           blocked_requests=blocked_requests,
                           top_malicious_urls=top_malicious_urls,
                           recent_attacks=recent_attacks)

@web.route("/logout")
def logout():
    session.pop("user_id", None)
    session.pop("username", None)
    return redirect(url_for("web.login")) 

@web.route("/admin")
@admin_required  # Apply the decorator to protect this admin route
def admin():
    db: Session = next(get_db())  # Get a new database session
    users = db.query(User).all()
    files = db.query(File).all()

    return render_template("admin.html", username=session["username"], users=users, files=files)

@web.route("/users", methods=["GET", "POST"])
@admin_required
def manage_users():
    db: Session = next(get_db())  # Get a new database session
    if request.method == "POST":
        user_id_to_delete = request.form.get("user_id_to_delete")

        user_to_delete = db.query(User).get(user_id_to_delete)
        if user_to_delete and user_to_delete.role_id != 1:  # Ensure the user is not an admin
            db.delete(user_to_delete)
            db.commit()
            return redirect(url_for("web.manage_users"))

    users = db.query(User).all()  # Retrieve all users

    return render_template("users.html", users=users)



@web.route('/visualize')
def visualize():
    # Get the filter type from the query parameters, defaulting to 'day'
    filter_type = request.args.get('filter', 'day')

    # Validate the filter type to ensure it is one of the allowed values
    allowed_filters = ['hour', 'day', 'week']
    if filter_type not in allowed_filters:
        filter_type = 'day'  # Reset to default if invalid

    # Generate visualizations
    log_img = visualize_logs(filter_type=filter_type)
    blocked_ip_img = visualize_blocked_ips(filter_type=filter_type)

    return render_template('visualize.html', 
                           log_img=log_img, 
                           blocked_ip_img=blocked_ip_img)