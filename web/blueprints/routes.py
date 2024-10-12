from flask import Blueprint, render_template, redirect, url_for, request, session ,jsonify , make_response
from database import db, bcrypt , User 
from web.utils import login_required , generate_otp, admin_required
import datetime


web = Blueprint('web', __name__)
api = Blueprint('api', __name__)


@web.route("/")
def index():
    return render_template("landing.html")


@web.before_request
def before_request():
    if 'user_id' in session and session.permanent:
        session.modified = True  # Reset the session timer on each request

    # Define a list of allowed endpoints for non-logged-in users
    allowed_endpoints = ['web.login', 'web.register', 'web.index' , 'web.faq']  # Add more endpoints as needed

    # Check if the user is not logged in and not accessing allowed endpoints
    if not session.get('user_id') and request.endpoint not in allowed_endpoints:
        return redirect(url_for('web.login'))

@web.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        
        # Check if the user exists
        user = User.query.filter((User.username == email) | (User.email == email)).first()

        if user:
            if bcrypt.check_password_hash(user.password, password):
                    db.session.commit()
                    session["user_id"] = user.id
                    session["username"] = user.username
                    return redirect(url_for("web.dashboard"))
            else:
                    return render_template("login.html", message="Incorrect username or password")
        else:
            return render_template("login.html", message="Incorrect username or password")

    return render_template("login.html")


@web.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        entered_otp = request.form.get("otp")  # Get the OTP entered by the user

        # For demonstration purposes, let's assume the generated OTP is stored in the db
        user = User.query.get(session.get('user_id'))

        if int(entered_otp) == user.otp:
            if user.role_id == 1:
                return redirect(url_for("web.dashboard"))
            else:
                return redirect(url_for("web.dashboard")) 
        else:
            # Incorrect OTP, display an error message
            return render_template("verify_otp.html", message="Incorrect OTP. Please try again.")

    return render_template("verify_otp.html")

@web.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")

        #remove bad characters
        for i in ["{","}","(",")","<",">","/","\\"]:
            if i in username:
                return render_template("register.html",message="Illegal characters in username")


        # Check if the username is already taken
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return render_template("register.html",message="Username already taken.")
        else:
            # Hash the password and create a new user
            hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
            new_user = User(username=username, password=hashed_password , email=email , date_registered=datetime.date.today())
            db.session.add(new_user)
            db.session.commit()
            return render_template("login.html", message="Await admin approval") # Redirect to the login route

    return render_template("register.html")





@web.route('/dashboard')
@login_required
def dashboard():
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
    session.pop("user_id",None)
    session.pop("username",None)
    session.pop("role",None)
    return redirect(url_for("web.login")) 

@web.route("/admin")
@admin_required  # Apply the decorator to protect this admin route
def admin():
    user = User.query.all()
    files = File.query.all()

    return render_template("admin.html", username= session["username"]) 



@web.route("/users", methods=["GET", "POST"])
@admin_required
def manage_users():
    if request.method == "POST":
        # Handle the user deletion based on the submitted form data
        user_id_to_delete = request.form.get("user_id_to_delete")
        
        # Check if the user_id_to_delete is valid (e.g., exists and is not the admin)
        user_to_delete = User.query.get(user_id_to_delete)
        user_to_delete_files = File.query.filter_by(owner_id=user_id_to_delete)
        if user_to_delete and user_to_delete.role != "admin":
            db.session.delete(user_to_delete)
            db.session.commit()
            #db.session.delete(user_to_delete_files)
            #db.session.commit
            #user_folder = os.path.join("uploads", user_to_delete.username)
            #os.rmdir(user_folder, exist_ok=True)
            

            # Redirect to the same page after user deletion
            return redirect(url_for("web.manage_users"))

    # Retrieve a list of all users from the database
    users = User.query.all()

    return render_template("users.html", users=users)

        


