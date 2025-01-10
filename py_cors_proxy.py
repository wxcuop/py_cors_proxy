from http.server import BaseHTTPRequestHandler, HTTPServer
from http.client import HTTPConnection
from urllib.parse import urlparse, urlencode
import urllib3
import json

class ProxyRequestHandler(BaseHTTPRequestHandler):
    def _set_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')

    def do_OPTIONS(self):
        self.send_response(204)
        self._set_cors_headers()
        self.end_headers()

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def do_PUT(self):
        self.handle_request()

    def do_DELETE(self):
        self.handle_request()

    def handle_request(self):
        parsed_url = urlparse(self.path)
        query = parsed_url.query
        target_url = self.headers.get('x-target-url')

        if not target_url:
            self.send_error(400, 'Missing x-target-url header')
            return

        parsed_target = urlparse(target_url)
        connection = HTTPConnection(parsed_target.netloc)

        # Determine method and prepare headers and body
        method = self.command
        headers = {key: value for key, value in self.headers.items() if key.lower() != 'host'}

        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else None

        # Forward request to the target server
        try:
            connection.request(method, parsed_target.path + '?' + query, body, headers)
            response = connection.getresponse()

            # Respond back to the client
            self.send_response(response.status)
            for header, value in response.getheaders():
                self.send_header(header, value)

            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(response.read())
        except Exception as e:
            self.send_error(502, f'Error forwarding request: {str(e)}')
        finally:
            connection.close()

if __name__ == "__main__":
    server_address = ('', 8080)  # Listen on all interfaces at port 8080
    httpd = HTTPServer(server_address, ProxyRequestHandler)
    print("Proxy server is running on port 8080")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down the server...")
        httpd.server_close()
