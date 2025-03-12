from fastapi import FastAPI, HTTPException
from typing import List
from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import datetime
from database import SessionLocal, Request, Blocked, User
from controllers.ml_model.waf import waf_model_predict
from starlette.middleware.cors import CORSMiddleware

app = FastAPI()



app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins (for local development)
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods (GET, POST, etc.)
    allow_headers=["*"],  # Allows all headers
)

# Pydantic model for request input data
class RequestData(BaseModel):
    url: str
    method: str
    headers: str
    body: str
    ip_address: str  # Ensure IP address is mandatory for logging


# Function to store request data into the "requests" table
def store_request_data(db_session: Session, data: RequestData):
    db_request = Request(
        url=data.url,
        method=data.method,
        headers=data.headers,
        body=data.body,
        ip_address=data.ip_address,  # Store the client IP here
        timestamp=datetime.utcnow()
    )
    db_session.add(db_request)
    db_session.commit()
    db_session.refresh(db_request)
    return db_request


# Function to add an entry to the "blocked" table
def add_blocked_entry(db_session: Session, url: str = None, ip_address: str = None, reason: str = "Malicious activity detected"):
    blocked_entry = Blocked(
        ip_address=ip_address,
        url=url,
        reason=reason,
        blocked_at=datetime.utcnow()
    )
    db_session.add(blocked_entry)
    db_session.commit()
    db_session.refresh(blocked_entry)


# Endpoint to store requests and log blocked entries for malicious activity
@app.post("/store-request")
def store_request(request_data: RequestData):
    db_session = SessionLocal()
    try:
        # Step 1: Store the request data including client IP
        stored_request = store_request_data(db_session, request_data)

        # Step 2: Check if the URL is malicious using your WAF model
        if request_data.url:
            try:
                result = waf_model_predict([request_data.url])
                if result[0]['res'] == 'Malicious request':
                    print(f"Blocked malicious URL: {request_data.url}")
                    # Add entry to the Blocked table
                    add_blocked_entry(
                        db_session,
                        url=request_data.url,
                        ip_address=request_data.ip_address,
                        reason="Malicious URL detected by WAF"
                    )
                    return {
                        "message": "Request stored and malicious URL blocked",
                        "status": "Blocked",
                        "url": request_data.url
                    }
                else:
                    print(f"Allowed URL: {request_data.url}")
                    return {
                        "message": "Request stored and URL allowed",
                        "status": "Allowed",
                        "url": request_data.url
                    }
            except Exception as e:
                print(f"Error during WAF prediction: {e}")
                raise HTTPException(status_code=500, detail="Error during WAF prediction")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to store request data")
    finally:
        db_session.close()


# Endpoint to retrieve all stored requests
@app.get("/get-requests")
def get_requests():
    db_session = SessionLocal()
    try:
        result = db_session.query(Request).all()
        return result
    finally:
        db_session.close()


# Endpoint to retrieve all blocked entries
@app.get("/get-blocked")
def get_blocked():
    db_session = SessionLocal()
    try:
        result = db_session.query(Blocked).all()
        return result
    finally:
        db_session.close()

class IpAddr(BaseModel):
    ips: List[str]

# Endpoint to unblock an IP address (via URL parameter)
@app.post("/unblock-ip")
def unblock_ip_endpoint( ip_addresses: IpAddr):
    db_session = SessionLocal()
    try:
        if not ip_addresses:
            raise HTTPException(status_code=400, detail="No IP addresses provided")
        
        print(ip_addresses)

        # Step 1: Query all rows matching the given IP addresses
        blocked_ips = db_session.query(Blocked).filter(Blocked.ip_address.in_(ip_addresses.ips)).all()

        if not blocked_ips:
            raise HTTPException(status_code=404, detail="No matching IP addresses found in the blocked list")

        # Step 2: Update the status to "unblocked" for all matching rows
        already_unblocked_ips = []
        updated_ips = []

        for blocked_ip in blocked_ips:
            if blocked_ip.status != "unblocked":
                blocked_ip.status = "unblocked"
                updated_ips.append(blocked_ip.ip_address)
            else:
                already_unblocked_ips.append(blocked_ip.ip_address)

        if not updated_ips:
            raise HTTPException(status_code=400, detail=f"All provided IPs are already unblocked: {', '.join(already_unblocked_ips)}")

        # Step 3: Commit the changes
        db_session.commit()

        return {
            "message": f"Successfully unblocked IP addresses: {', '.join(updated_ips)}",
            "already_unblocked": already_unblocked_ips
        }
    finally:
        db_session.close()




@app.post("/block-ip")
def unblock_ip_endpoint( ip_addresses: IpAddr):
    db_session = SessionLocal()
    try:
        if not ip_addresses:
            raise HTTPException(status_code=400, detail="No IP addresses provided")
        
        print(ip_addresses)

        # Step 1: Query all rows matching the given IP addresses
        blocked_ips = db_session.query(Blocked).filter(Blocked.ip_address.in_(ip_addresses.ips)).all()

        if not blocked_ips:
            raise HTTPException(status_code=404, detail="No matching IP addresses found in the blocked list")

        # Step 2: Update the status to "unblocked" for all matching rows
        already_unblocked_ips = []
        updated_ips = []

        for blocked_ip in blocked_ips:
            if blocked_ip.status == "unblocked":
                blocked_ip.status = "blocked"
                updated_ips.append(blocked_ip.ip_address)
            else:
                already_unblocked_ips.append(blocked_ip.ip_address)

        if not updated_ips:
            raise HTTPException(status_code=400, detail=f"All provided IPs are already blocked: {', '.join(already_unblocked_ips)}")

        # Step 3: Commit the changes
        db_session.commit()

        return {
            "message": f"Successfully blocked IP addresses: {', '.join(updated_ips)}",
            "already_unblocked": already_unblocked_ips
        }
    finally:
        db_session.close()