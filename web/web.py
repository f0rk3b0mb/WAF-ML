from flask import Flask, request, jsonify, render_template, session, send_file
from flask_bcrypt import Bcrypt
from database import User , Blocked , Request,engine
from flask_cors import CORS
from sqlalchemy.orm import scoped_session, sessionmaker
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import io
from reportlab.lib import colors
from datetime import datetime
from utils import login_required , admin_required
import os
from dotenv import load_dotenv




app = Flask(__name__,static_folder="templates", static_url_path="/")  
CORS(app,origins="*",supports_credentials=True)
load_dotenv()
app.secret_key = os.getenv("SECRET_KEY")


bcrypt = Bcrypt(app)
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

    return jsonify({"id": user.id, "username": user.username , "email": user.email, "is_admin": user.is_admin, "approved": user.active})


@app.route("/api/register", methods=["POST"])
def register():
    db = SessionLocal()
    email = request.form.get("email")
    username = request.form.get("username")
    password = request.form.get("password")
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(email=email, username=username, password=password_hash, is_admin=0, active=0)
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
        return jsonify({
            "id": user.id, 
            "username": user.username,
            "is_admin": user.is_admin
        })
    else:
        return jsonify({"error": "Unauthorized"}), 401
    


@app.route("/api/requests")
@login_required
def get_requests():
    db_session = SessionLocal()
    try:
        result = db_session.query(Request).all()
        return jsonify([{ 
            "id": req.id, 
            "ip_address": req.ip_address, 
            "url": req.url, 
            "method": req.method, 
            "timestamp": req.timestamp.strftime("%Y-%m-%dT%H:%M:%S")  # Ensure timestamp is included
        } for req in result])
    finally:
        db_session.close()

@app.route("/api/blocked")
@login_required
def get_blocked():
    db_session = SessionLocal()
    try:
        result = db_session.query(Blocked).all()
        return jsonify([{ 
            "id": blk.id, 
            "ip_address": blk.ip_address, 
            "url": blk.url, 
            "reason": blk.reason,
            "blocked_at": blk.blocked_at.strftime("%Y-%m-%d %H:%M:%S"),
            "status": blk.status 
        } for blk in result])
    finally:
        db_session.close()


@app.route("/api/unblock", methods=["POST"])
@login_required
def unblock():
    db_session = SessionLocal()
    try:
        ip_data = request.json
        if not ip_data:
            return jsonify({"error": "No IP provided"}), 400

        blocked_ips = db_session.query(Blocked).filter(Blocked.ip_address.in_(ip_data["ips"])).all()

        if not blocked_ips:
            return jsonify({"error": "No matching IPs found"}), 404

        for blocked_ip in blocked_ips:
            blocked_ip.status = "unblocked"
        
        db_session.commit()
        return jsonify({"success": "Unblocked"})
    finally:
        db_session.close()

@app.route("/api/block", methods=["POST"])
@login_required
def block():
    db_session = SessionLocal()
    try:
        ip_data = request.json
        if not ip_data:
            return jsonify({"error": "No IP provided"}), 400

        blocked_ips = db_session.query(Blocked).filter(Blocked.ip_address.in_(ip_data["ips"])).all()

        for blocked_ip in blocked_ips:
            blocked_ip.status = "blocked"
        
        db_session.commit()
        return jsonify({"success": "Blocked"})
    finally:
        db_session.close()

@app.route("/api/report")
@admin_required
def report():
    db_session = SessionLocal()
    try:
        # Get date range parameters from query string
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # Base query for blocked entries
        blocked_query = db_session.query(Blocked)
        
        # Apply date filters if provided
        if start_date:
            blocked_query = blocked_query.filter(Blocked.blocked_at >= datetime.strptime(start_date, "%Y-%m-%d"))
        if end_date:
            blocked_query = blocked_query.filter(Blocked.blocked_at <= datetime.strptime(end_date, "%Y-%m-%d"))
        
        # Get filtered blocked entries
        blocked_entries = blocked_query.all()

        report_data = {
            "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "date_range": {
                "start": start_date or "All time",
                "end": end_date or "All time"
            },
            "total_blocked": len(blocked_entries),
            "blocked_entries": [
                { 
                    "id": blk.id, 
                    "ip_address": blk.ip_address, 
                    "url": blk.url,
                    "reason": blk.reason,
                    "blocked_at": blk.blocked_at.strftime("%Y-%m-%d %H:%M:%S"),
                    "status": blk.status
                }
                for blk in blocked_entries
            ]
        }
        pdf_buffer = generate_pdf(report_data)
        return send_file(pdf_buffer, as_attachment=True, download_name="waf_report.pdf", mimetype="application/pdf")
    finally:
        db_session.close()

def generate_pdf(report_data):
    pdf_buffer = io.BytesIO()
    c = canvas.Canvas(pdf_buffer, pagesize=letter)
    width, height = letter
    
    # Title with color
    c.setFillColor(colors.darkblue)
    c.setFont("Helvetica-Bold", 18)
    c.drawString(180, height - 50, "Web Application Firewall Report")
    
    # Metadata with color
    c.setFillColor(colors.black)
    c.setFont("Helvetica", 12)
    c.drawString(50, height - 80, f"Generated At: {report_data['generated_at']}")
    c.drawString(50, height - 100, f"Date Range: {report_data['date_range']['start']} to {report_data['date_range']['end']}")
    c.setFillColor(colors.red)
    c.drawString(50, height - 120, f"Total Blocked Entries: {report_data['total_blocked']}")
    
    y_position = height - 150
    
    # Blocked Entries Section with color
    c.setFillColor(colors.darkred)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y_position, "Blocked Entries:")
    y_position -= 20
    c.setFillColor(colors.black)
    c.setFont("Helvetica", 10)
    
    for blk in report_data['blocked_entries']:
        # Draw entry details with improved formatting
        c.drawString(50, y_position, f"ID: {blk['id']}")
        y_position -= 15
        c.drawString(70, y_position, f"IP Address: {blk['ip_address']}")
        y_position -= 15
        c.drawString(70, y_position, f"URL: {blk['url'][:100]}...")  # Truncate long URLs
        y_position -= 15
        c.drawString(70, y_position, f"Reason: {blk['reason']}")
        y_position -= 15
        c.drawString(70, y_position, f"Blocked At: {blk['blocked_at']}")
        y_position -= 15
        c.drawString(70, y_position, f"Status: {blk['status']}")
        y_position -= 20  # Add extra space between entries
        
        if y_position < 50:  # Move to next page if needed
            c.showPage()
            y_position = height - 50
            c.setFont("Helvetica", 10)
    
    c.save()
    pdf_buffer.seek(0)
    return pdf_buffer

@app.route("/api/logout")
@login_required
def logout():
    session.clear()
    return jsonify({"success": "Logged out"})

@app.route("/api/users", methods=["GET"])
@admin_required
def get_users():
    db = SessionLocal()
    try:
        users = db.query(User).all()
        return jsonify([{
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_admin" : user.is_admin
        } for user in users])
    finally:
        db.close()

@app.route("/api/users/<int:user_id>", methods=["PUT"])
@login_required
def update_user(user_id):
    db = SessionLocal()
    try:
        # Check if user is updating their own profile or is admin
        current_user_id = session.get('user_id')
        current_user = db.query(User).filter(User.id == current_user_id).first()
        
        if not current_user:
            return jsonify({"error": "Current user not found"}), 404

        # If user is not admin and trying to update another user's profile
        if current_user_id != user_id and not current_user.is_admin:
            return jsonify({"error": "Unauthorized"}), 403

        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({"error": "User not found"}), 404

        data = request.json
        if "username" in data:
            user.username = data["username"]
        if "email" in data:
            user.email = data["email"]
        if "password" in data:
            user.password = bcrypt.generate_password_hash(data["password"]).decode('utf-8')
        if "is_admin" in data:
            # Only allow admins to modify admin status
            if not current_user.is_admin:
                return jsonify({"error": "Only admins can modify admin status"}), 403
            user.is_admin = data["is_admin"]

        db.commit()
        return jsonify({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_admin": user.is_admin
        })
    finally:
        db.close()

@app.route("/api/users/<int:user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return jsonify({"error": "User not found"}), 404

        # Prevent admin from deleting themselves
        if user_id == session.get('user_id'):
            return jsonify({"error": "Cannot delete your own account"}), 400

        db.delete(user)
        db.commit()
        return jsonify({"success": "User deleted"})
    finally:
        db.close()

def run_flask():
    app.run("0.0.0.0", 1234)
