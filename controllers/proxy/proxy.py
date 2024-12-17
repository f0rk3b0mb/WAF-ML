import asyncio
import aiohttp
from urllib.parse import urlparse

class ProxyHandler:
    def __init__(self, reader, writer, fastapi_url="http://127.0.0.1:8000"):
        self.reader = reader
        self.writer = writer
        self.fastapi_url = fastapi_url
        self.blocked_ips = set()

    async def handle_request(self):
        client_ip, _ = self.writer.get_extra_info('peername')  # Extract client IP address
        print(f"Connection established with {client_ip}")
        
        # Read the request from the client
        request = await self.reader.read(8192)  # Increased buffer size
        if request:
            print(f"Received request from {client_ip}:\n{request.decode()}")
            await self.process_request(request.decode(), client_ip)  # Pass IP to process_request()
        else:
            print(f"Empty request received from {client_ip}")
            self.writer.close()
    
    async def fetch_blocked_ips(self):
        # Use aiohttp to make an HTTP request to the /get-blocked FastAPI endpoint
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.fastapi_url}/get-blocked") as response:
                if response.status == 200:
                    blocked_entries = await response.json()  # Parse the JSON response
                    # Extract just the IP addresses from the response
                    self.blocked_ips = {entry['ip_address'] for entry in blocked_entries if entry['status'] == 'blocked'}
                else:
                    print(f"Failed to fetch blocked IPs. Status code: {response.status}")

    async def process_request(self, request, client_ip):
        await self.fetch_blocked_ips()

        # Check if the client's IP is blocked
        if client_ip in self.blocked_ips:
            print(f"Blocked request from {client_ip}")
            # Send custom error page for blocked IPs
            error_page = self.get_custom_error_page()

            # Send 403 Forbidden status and custom error page
            self.writer.write("HTTP/1.1 403 Forbidden\r\n".encode("utf-8"))
            self.writer.write("Content-Type: text/html\r\n\r\n".encode("utf-8"))
            self.writer.write(error_page.encode("utf-8"))
            await self.writer.drain()
            self.writer.close()
            return
        
        lines = request.splitlines()
        if lines:
            first_line = lines[0]
            method, url, _ = first_line.split()

            # Parse URL
            parsed_url = urlparse(url)
            #hostname = parsed_url.hostname if parsed_url.hostname else "127.0.0.1"
            #port = parsed_url.port if parsed_url.port else 80
            #path = parsed_url.path if parsed_url.path else "/"

            hostname="127.0.0.1"
            port=9999
            path = parsed_url.path if parsed_url.path else "/"

            print(f"Forwarding {method} request to {hostname}:{port}{path}")

            request_data = {
                "url": url,
                "method": method,
                "headers": "\r\n".join(lines[1:]),
                "body": lines[-1] if len(lines) > 1 else "",
                "client_ip": client_ip  # Log the client's IP address here
            }

            # Log the request in FastAPI before forwarding it
            await self.log_request_to_fastapi(request_data, client_ip)
            # Forward request to the destination server
            try:
                response = await self.forward_request(method, hostname, port, path, lines)
                self.writer.write(response)
                await self.writer.drain()
                print(f"Response sent to {client_ip}: {len(response)} bytes")
            except Exception as e:
                error_msg = f"Error forwarding request: {e}"
                print(error_msg)
                self.writer.write(f"HTTP/1.1 500 Internal Server Error\r\n\r\n{error_msg}".encode("utf-8"))
                await self.writer.drain()
            finally:
                self.writer.close()

    def get_custom_error_page(self):
    # Return a custom error page HTML as a string with improved styling
        return """
    <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>403 Forbidden</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f4;
                    color: #333;
                    margin: 0;
                    padding: 0;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    text-align: center;
                }
                .container {
                    background-color: white;
                    border-radius: 8px;
                    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                    padding: 30px;
                    max-width: 500px;
                    width: 100%;
                }
                h1 {
                    font-size: 48px;
                    margin-bottom: 20px;
                    color: #d9534f;
                }
                p {
                    font-size: 18px;
                    margin-bottom: 30px;
                }
                .error-code {
                    font-size: 100px;
                    color: #d9534f;
                    margin: 0;
                }
                .btn {
                    background-color: #007bff;
                    color: white;
                    padding: 10px 20px;
                    font-size: 16px;
                    text-decoration: none;
                    border-radius: 4px;
                    display: inline-block;
                    margin-top: 20px;
                }
                .btn:hover {
                    background-color: #0056b3;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="error-code">403</div>
                <h1>Forbidden</h1>
                <p>Your IP address is blocked from accessing this resource.</p>
                <p>If you believe this is a mistake, please contact support.</p>
                <a href="/" class="btn">Go Back to Home</a>
            </div>
        </body>
    </html>
    """


    async def forward_request(self, method, hostname, port, path, request_lines):
        # Prepare the headers
        headers = "\r\n".join(request_lines[1:])
        sanitized_headers = self.sanitize_headers(headers)

        if method == "GET":
            # Forward a GET request
            response = await self.send_get_request(hostname, port, path, sanitized_headers)
        elif method == "POST":
            # Forward a POST request
            body = request_lines[-1] if len(request_lines) > 1 else ""
            response = await self.send_post_request(hostname, port, path, sanitized_headers, body)
        else:
            # Handle unsupported HTTP methods with a 405 Method Not Allowed
            return f"HTTP/1.1 405 Method Not Allowed\r\n\r\nUnsupported HTTP method: {method}".encode("utf-8")
        
        return response

    def sanitize_headers(self, headers):
        sanitized = {}
        for header in headers.split("\r\n"):
            if ": " in header:
                key, value = header.split(": ", 1)
                sanitized[key.strip()] = value.strip()
        return sanitized

    async def send_get_request(self, hostname, port, path, headers):
        print(f"Sending GET request to {hostname}:{port}{path}")
        url = f"http://{hostname}:{port}{path}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as response:
                return await self.build_response(response)

    async def send_post_request(self, hostname, port, path, headers, body):
        print(f"Sending POST request to {hostname}:{port}{path}")
        url = f"http://{hostname}:{port}{path}"
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, data=body) as response:
                return await self.build_response(response)

    async def build_response(self, response):
        # Construct a full HTTP response with the status code, headers, and body.
        response_content = await response.read()
        status_code = f"HTTP/1.1 {response.status} {response.reason}"
        headers = "\r\n".join([f"{key}: {value}" for key, value in response.headers.items()])
        full_response = f"{status_code}\r\n{headers}\r\n\r\n".encode("utf-8") + response_content
        return full_response
    
    async def log_request_to_fastapi(self, request_data, client_ip):
        # Send request data to FastAPI for logging
        async with aiohttp.ClientSession() as session:
            try:
                request_data["ip_address"] = client_ip  # Include the client IP in the log data
                async with session.post(f"{self.fastapi_url}/store-request", json=request_data) as response:
                    if response.status == 200:
                        print(f"Request data from {client_ip} logged successfully")
                    else:
                        print(f"Failed to log request data: {response.status}")
            except Exception as e:
                print(f"Error logging request data: {e}")

class ProxyServer:
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port

    async def start(self):
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        print(f"Proxy server listening on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()

    async def handle_client(self, reader, writer):
        handler = ProxyHandler(reader, writer)
        await handler.handle_request()


async def start_proxy():
    proxy_server = ProxyServer()
    await proxy_server.start()
