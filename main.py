import asyncio
import uvicorn
import threading
from controllers.proxy.proxy import start_proxy  # Import the proxy server
from controllers.api.firewall import app as fastapi_app  # Import FastAPI app
from database import init_db
from controllers.ml_model.waf import WAF
from web.web import run_flask  # Your Flask app

# Function to run FastAPI using Uvicorn in the background
async def start_fastapi():
    # Configure and run the FastAPI server using Uvicorn
    config = uvicorn.Config("controllers.api.firewall:app", host="0.0.0.0", port=8000, reload=True)
    server = uvicorn.Server(config)
    await server.serve()

# Function to start Flask in a separate thread
def start_flask():
    threading.Thread(target=run_flask, daemon=True).start()

async def main():
    start_flask()  # Start Flask in a separate thread
    # Run both the proxy and FastAPI server concurrently
    proxy_task = asyncio.create_task(start_proxy())  # Start proxy server
    fastapi_task = asyncio.create_task(start_fastapi())  # Start FastAPI server

    # Wait for both tasks to finish
    await asyncio.gather(proxy_task, fastapi_task)

if __name__ == "__main__":
    asyncio.run(init_db())  # Initialize database (if async)
    asyncio.run(main())  # Run both FastAPI and proxy concurrently

