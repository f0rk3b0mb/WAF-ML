from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from datetime import datetime
from database import SessionLocal, Request, Blocked 
from controllers.ml_model.waf import waf_model_predict  
app = FastAPI()
#from utils import block_ip, unblock_ip

# Pydantic model for request input data
class RequestData(BaseModel):
    url: str
    method: str
    headers: str
    body: str
    ip_address: str  # Ensure IP address is mandatory for logging


# Function to store request data into the "requests" table
async def store_request_data(db_session: AsyncSession, data: RequestData):
    db_request = Request(
        url=data.url,
        method=data.method,
        headers=data.headers,
        body=data.body,
        ip_address=data.ip_address,  # Store the client IP here
        timestamp=datetime.utcnow()
    )
    db_session.add(db_request)
    await db_session.commit()
    await db_session.refresh(db_request)
    return db_request


# Function to add an entry to the "blocked" table
async def add_blocked_entry(db_session: AsyncSession, url: str = None, ip_address: str = None, reason: str = "Malicious activity detected"):
    blocked_entry = Blocked(
        ip_address=ip_address,
        url=url,
        reason=reason,
        blocked_at=datetime.utcnow()
    )
    db_session.add(blocked_entry)
    await db_session.commit()
    await db_session.refresh(blocked_entry)


# Endpoint to store requests and log blocked entries for malicious activity
@app.post("/store-request")
async def store_request(request_data: RequestData):
    async with SessionLocal() as db_session:
        try:
            # Step 1: Store the request data including client IP
            stored_request = await store_request_data(db_session, request_data)

            # Step 2: Check if the URL is malicious using your WAF model
            if request_data.url:
                try:
                    result = waf_model_predict([request_data.url])
                    if result[0]['res'] == 'Malicious request':
                        print(f"Blocked malicious URL: {request_data.url}")
                        #block_ip(request_data.ip_address)
                        # Add entry to the Blocked table
                        await add_blocked_entry(
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


# Endpoint to retrieve all stored requests
@app.get("/get-requests")
async def get_requests():
    async with SessionLocal() as db_session:
        result = await db_session.execute(select(Request))
        requests = result.scalars().all()
        return requests


# Endpoint to retrieve all blocked entries
@app.get("/get-blocked")
async def get_blocked():
    async with SessionLocal() as db_session:
        result = await db_session.execute(select(Blocked))
        blocked_entries = result.scalars().all()
        return blocked_entries


# Endpoint to unblock an IP address (via URL parameter)
@app.put("/unblock-ip/{ip_address}")
async def unblock_ip_endpoint(ip_address: str):
    async with SessionLocal() as db_session:
        # Step 1: Query all rows with the given IP address
        result = await db_session.execute(select(Blocked).filter(Blocked.ip_address == ip_address))
        blocked_ips = result.scalars().all()

        if not blocked_ips:
            raise HTTPException(status_code=404, detail="IP address not found in blocked list")

        # Step 2: Update the status to "unblocked" for all matching rows
        already_unblocked = True  # To track if all rows are already unblocked

        for blocked_ip in blocked_ips:
            if blocked_ip.status != "unblocked":
                blocked_ip.status = "unblocked"
                already_unblocked = False

        if already_unblocked:
            raise HTTPException(status_code=400, detail="IP address is already unblocked in all rows")

        # Step 3: Commit the changes
        await db_session.commit()

        return {"message": f"All rows with IP address {ip_address} have been unblocked successfully."}
