#import subprocess



#def block_ip(ip):
#    try:
#        # Blocking the IP using iptables
#        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
#        print(f"Blocked IP: {ip}")
#
#        # Log the blocked IP to the database
#
#        print(f"Logged blocked IP: {ip} to the database")
#
#    except Exception as e:
#        print(f"Failed to block IP {ip}: {e}")
#
#
#
#
#def unblock_ip(ip):
#    try:
#        # Unblocking the IP using iptables
#        subprocess.run(['sudo','iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
#        print(f"Unblocked IP: {ip}")
#    except Exception as e:
#        print(f"Failed to unblock IP {ip}: {e}")


import hashlib
from cryptography.fernet import Fernet
import os
from io import BytesIO
from flask import make_response
from functools import wraps
from flask import session, redirect, url_for
from database import User
import pyotp


# encryptor
#SECRET_KEY = Fernet.generate_key()
SECRET_KEY = "oGSklXeLBa-OxD4_HQ0yqnlhesuWA1UgTtp1VBDFA1Y="
cipher_suite = Fernet(SECRET_KEY)

#login check

def login_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return decorated_function


def admin_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")

        if user_id is None:
            return redirect(url_for("login"))

        user = User.query.get(user_id)

        if not user:
            return redirect(url_for("login"))

        if session.get("role") != 1:
            return "Only admin is allowed to access this page"

        return func(*args, **kwargs)
    return decorated_function

def generate_otp():
    # Replace this with your secret key used for OTP generation
    secret_key = "SQTNQFNVUB3CTYMRRCY5VJ7C7MPE4WWC" # store in environ

    # Create a TOTP object using the secret key and the user's email
    totp = pyotp.TOTP(secret_key)

    # Generate the OTP
    otp_code = totp.now()

    return otp_code