from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_bcrypt import Bcrypt
from flask_session import Session
from database import User , engine
from flask_cors import CORS , cross_origin
from sqlalchemy.orm import scoped_session, sessionmaker
import requests
import json



app = Flask(__name__,static_folder="templates", static_url_path="/")  
CORS(app,origins="*",supports_credentials=True)
app.secret_key = "jdfkfkkigkjgjkjg"


bcrypt = Bcrypt(app)
#server_session=Session(app)
SessionLocal = scoped_session(sessionmaker(bind=engine))
app.config['SESSION_COOKIE_HTTPONLY'] = False




def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()



@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/@me")
def get_current_user():
    user_id = session.get('user_id')
    db = SessionLocal()

    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    user= db.query(User).filter(User.id == user_id).first()

    return jsonify({"id": user.id, "username": user.username , "email": user.email})


@app.route("/api/register", methods=["POST"])
def register():
    db = SessionLocal()
    email = request.form.get("email")
    username = request.form.get("username")
    password = request.form.get("password")
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(email=email, username=username, password=password_hash)
    db.add(user)
    db.commit()
    db.close()
    return jsonify({"success": "User created"})


@app.route("/api/login", methods=["POST"])
def login():
    db = SessionLocal()
    email_or_username = request.form.get("email")
    password = request.form.get("password")

    user = db.query(User).filter((User.username == email_or_username) | (User.email == email_or_username)).first()

    db.close()

    if user and bcrypt.check_password_hash(user.password, password):
        session['user_id'] = user.id
        return jsonify({"id": user.id, "username": user.username})
    else:
        return jsonify({"error": "Unauthorized"}), 401
    


@app.route("/blocked")
def blocked():
    r = requests.get("http://127.0.0.1:8000/get-blocked")
    return r.json()


@app.route("/requests")
def req():
    r = requests.get("http://127.0.0.1:8000/get-requests")
    return r.json()



@app.route("/api/unblock", methods=["POST"])  
def unblock():
    ip = request.json
    
    
    if not ip:
        return jsonify({"error": "No IP provided"}), 400  

    # Forward the request with correct format  
    r = requests.post("http://127.0.0.1:8000/unblock-ip", data=json.dumps(ip), headers={"Content-Type": "application/json"})

    if r.status_code != 200:  
        return jsonify({"error": r.json()["detail"]}), 400
    else:
        return jsonify({"success": f"Unblocked"})


@app.route("/api/block", methods=["POST"])
def block():
    ip = request.json
    if not ip:
        return jsonify({"error": "No IP provided"}), 400
    
    r = requests.post("http://127.0.0.1:8000/block-ip", data=json.dumps(ip), headers={"Content-Type": "application/json"})

    if r.status_code != 200:
        return jsonify({"error": r.json()["detail"]}), 400
    else:
        return jsonify({"success": f"Blocked"})

@app.route("/logout")
def logout():
    session.clear()
    return jsonify({"success": "Logged out"})


def run_flask():
    app.run("0.0.0.0", 1234)
