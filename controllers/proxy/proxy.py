import asyncio
import aiohttp
from urllib.parse import urlparse

class ProxyHandler:
    def __init__(self, reader, writer, fastapi_url="http://127.0.0.1:8000/store-request"):
        self.reader = reader
        self.writer = writer
        self.fastapi_url = fastapi_url

    async def handle_request(self):
        print(f"Connection established with {self.writer.get_extra_info('peername')}")
        
        # Read data from the client
        request = await self.reader.read(4096)
        if request:
            print(f"Received request:\n{request.decode()}")
            await self.process_request(request.decode())
        else:
            print(f"Empty request received")
            self.writer.close()

    async def process_request(self, request):
        lines = request.splitlines()
        if lines:
            first_line = lines[0]
            method, url, _ = first_line.split()

            # Parse URL
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname if parsed_url.hostname else "198.177.123.57"
            port = parsed_url.port if parsed_url.port else 80
            path = parsed_url.path if parsed_url.path else "/"

            print(f"Forwarding {method} request to {hostname}:{port}{path}")


            request_data = {
                "url": url,
                "method": method,
                "headers": "\r\n".join(lines[1:]),
                "body": lines[-1] if len(lines) > 1 else ""
            }

            # Log the request in FastAPI before forwarding it
            await self.log_request_to_fastapi(request_data)
            # Forward request to the destination server
            try:
                response = await self.forward_request(method, hostname, port, path, lines)
                self.writer.write(response)
                await self.writer.drain()
                print(f"Response sent to client: {len(response)} bytes")
            except Exception as e:
                error_msg = f"Error forwarding request: {e}"
                print(error_msg)
                self.writer.write(f"HTTP/1.1 500 Internal Server Error\r\n\r\n{error_msg}".encode("utf-8"))
                await self.writer.drain()
            finally:
                self.writer.close()

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
            raise Exception(f"Unsupported HTTP method: {method}")
        
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
    
    async def log_request_to_fastapi(self, request_data):
        # Send request data to FastAPI for logging
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(self.fastapi_url, json=request_data) as response:
                    if response.status == 200:
                        print("Request data logged successfully")
                    else:
                        print(f"Failed to log request data: {response.status}")
            except Exception as e:
                print(f"Error logging request data: {e}")

class ProxyServer:
    def __init__(self, host='127.0.0.1', port=8080):
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
