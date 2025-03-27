from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
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


@app.get("/get-blocked")
def get_blocked():
    db_session = SessionLocal()
    try:
        result = db_session.query(Blocked).all()
        return result
    finally:
        db_session.close()
