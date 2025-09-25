import asyncio
import uvicorn
import threading
import signal
from controllers.proxy.proxy import start_proxy  # Import the proxy server
from controllers.api.firewall import app as fastapi_app  # Import FastAPI app
from database import init_db
from controllers.ml_model.waf import WAF
from web.web import run_flask  # Your Flask app

# Global variables to track running services
flask_thread = None
proxy_task = None
fastapi_task = None

# Function to run FastAPI using Uvicorn in the background
async def start_fastapi():
    # Configure and run the FastAPI server using Uvicorn
    config = uvicorn.Config("controllers.api.firewall:app", host="127.0.0.1", port=8000, reload=True)
    server = uvicorn.Server(config)
    await server.serve()

# Function to start Flask in a separate thread
def start_flask():
    global flask_thread
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()

async def shutdown(signal, loop):
    """Cleanup tasks tied to the service's shutdown."""
    print(f"\nReceived exit signal {signal.name}...")
    
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    [task.cancel() for task in tasks]
    
    print(f"Cancelling {len(tasks)} outstanding tasks")
    await asyncio.gather(*tasks, return_exceptions=True)
    
    loop.stop()

async def main():
    # Get the event loop
    loop = asyncio.get_running_loop()
    
    # Add signal handlers
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(
            sig,
            lambda s=sig: asyncio.create_task(shutdown(s, loop))
        )
    
    try:
        start_flask()  # Start Flask in a separate thread
        # Run both the proxy and FastAPI server concurrently
        global proxy_task, fastapi_task
        proxy_task = asyncio.create_task(start_proxy())  # Start proxy server
        fastapi_task = asyncio.create_task(start_fastapi())  # Start FastAPI server

        # Wait for both tasks to finish
        await asyncio.gather(proxy_task, fastapi_task)
    except asyncio.CancelledError:
        print("Tasks were cancelled")
    finally:
        print("Shutting down gracefully...")

if __name__ == "__main__":
    try:
        init_db()  # Initialize database (if async)
        asyncio.run(main())  # Run both FastAPI and proxy concurrently
    except KeyboardInterrupt:
        print("\nReceived keyboard interrupt. Shutting down...")
    except Exception as e:
        print(f"\nAn error occurred: {e}")
    finally:
        print("Application shutdown complete.")

