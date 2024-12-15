# controllers/api/firewall.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from database import SessionLocal, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import create_engine
#from utils  import block_ip , unblock_ip
from controllers.ml_model.waf import WAF


app = FastAPI()
waf_model = WAF()

# Define model to request data
class RequestData(BaseModel):
    url: str
    method: str
    headers: str
    body: str

# Function to store request data in the database
async def store_request_data(db_session: AsyncSession, data: RequestData):
    db_request = Request(
        url=data.url,
        method=data.method,
        headers=data.headers,
        body=data.body
    )
    db_session.add(db_request)
    await db_session.commit()

#store-logs

@app.post("/store-request")
async def store_request(request_data: RequestData):
    if request_data.url:
            try:
                # Make prediction using your WAF's ML model
                result = waf_model.predict([request_data.url])
                if result[0]['res'] == 'Malicious request':
                    print(f"Blocked malicious URL: {request_data.url}")
                    # Implement logic to block the IP or drop the packet (optional)
                    #block_ip(source_ip)
                else:
                    print(f"Allowed URL: {request_data.url}")
            except Exception as e:
                print(f"Error during prediction: {e}")



    async with SessionLocal() as db_session:
        try:
            await store_request_data(db_session, request_data)
            return {"message": "Request data stored successfully"}
        except Exception as e:
            raise HTTPException(status_code=500, detail="Failed to store request data")


#read db

@app.get("/get-requests")
async def get_requests():
    async with SessionLocal() as db_session:
        result = await db_session.execute(select(Request))
        requests = result.scalars().all()
        return requests


# Route to classify incoming queries using the machine learning model
async def classify_query(url):
    try:
        # Classify the queries using the loaded WAF model
        results = waf_model.predict(url)
        return {"classification_results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error classifying query: {e}")


