import asyncio
import uvicorn
from controllers.proxy.proxy import start_proxy  # Import the proxy server
from controllers.api.firewall import app  # Import FastAPI app from fastapi_server.py
from database import init_db
import asyncio
from controllers.ml_model.waf import WAF

async def start_fastapi():
    # Run the FastAPI server in the background using Uvicorn
    config = uvicorn.Config("controllers.api.firewall:app", host="0.0.0.0", port=8000, reload=True)
    server = uvicorn.Server(config)
    await server.serve()

async def main():
    # Run both the proxy and FastAPI server concurrently
    proxy_task = asyncio.create_task(start_proxy())  # Start proxy server
    fastapi_task = asyncio.create_task(start_fastapi())  # Start FastAPI server

    # Wait for both tasks to finish
    await asyncio.gather(proxy_task, fastapi_task)

if __name__ == "__main__":
    asyncio.run(init_db())
    asyncio.run(main())
