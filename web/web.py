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
    


@app.route("/api/requests")
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
def report():
    db_session = SessionLocal()
    try:
        requests = db_session.query(Request).all()
        blocked_entries = db_session.query(Blocked).all()

        report_data = {
            "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "total_requests": len(requests),
            "total_blocked": len(blocked_entries),
            "requests": [
                { "id": req.id, "ip_address": req.ip_address, "url": req.url, "method": req.method }
                for req in requests
            ],
            "blocked_entries": [
                { "id": blk.id, "ip_address": blk.ip_address, "reason": blk.reason }
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
    c.setFillColor(colors.green)
    c.drawString(50, height - 100, f"Total Requests: {report_data['total_requests']}")
    c.setFillColor(colors.red)
    c.drawString(50, height - 120, f"Total Blocked: {report_data['total_blocked']}")
    
    y_position = height - 150
    
    # Requests Section with color
    c.setFillColor(colors.darkgreen)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y_position, "Requests:")
    y_position -= 20
    c.setFillColor(colors.black)
    c.setFont("Helvetica", 10)
    for req in report_data['requests'][:10]:  # Limiting to 10 for readability
        c.drawString(50, y_position, f"ID: {req['id']}, IP: {req['ip_address']}, URL: {req['url']}, Method: {req['method']}")
        y_position -= 15
        if y_position < 50:  # Move to next page if needed
            c.showPage()
            y_position = height - 50
            c.setFont("Helvetica", 10)
    
    # Blocked Entries Section with color
    y_position -= 20
    c.setFillColor(colors.darkred)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y_position, "Blocked Entries:")
    y_position -= 20
    c.setFillColor(colors.black)
    c.setFont("Helvetica", 10)
    for blk in report_data['blocked_entries'][:10]:  # Limiting to 10 for readability
        c.drawString(50, y_position, f"ID: {blk['id']}, IP: {blk['ip_address']}, Reason: {blk['reason']}")
        y_position -= 15
        if y_position < 50:
            c.showPage()
            y_position = height - 50
            c.setFont("Helvetica", 10)
    
    c.save()
    pdf_buffer.seek(0)
    return pdf_buffer

@app.route("/logout")
def logout():
    session.clear()
    return jsonify({"success": "Logged out"})


def run_flask():
    app.run("0.0.0.0", 1234)
