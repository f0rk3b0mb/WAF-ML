
import os
from flask import make_response
from functools import wraps
from flask import session, redirect, url_for
from database import User
import pyotp


def login_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("web.login"))
        return func(*args, **kwargs)
    return decorated_function


def admin_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")

        if user_id is None:
            return redirect(url_for("web.login"))

        user = User.query.get(user_id)

        if not user:
            return redirect(url_for("web.login"))

        if session.get("role") != 1:
            return "Only admin is allowed to access this page"

        return func(*args, **kwargs)
    return decorated_function

def generate_otp():
    # Replace this with your secret key used for OTP generation
    secret_key = os.environ['OTP_SECRET_KEY']

    # Create a TOTP object using the secret key and the user's email
    totp = pyotp.TOTP(secret_key)

    # Generate the OTP
    otp_code = totp.now()

    return otp_code