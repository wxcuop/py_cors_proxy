from http.server import BaseHTTPRequestHandler, HTTPServer
from http.client import HTTPConnection
from urllib.parse import urlparse
import logging

# Initialize logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


class ProxyRequestHandler(BaseHTTPRequestHandler):
    def _set_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, x-target-url")

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
        target_url = self.headers.get("x-target-url")

        if not target_url:
            self.send_error(400, "Missing x-target-url header")
            logging.error("Request missing x-target-url header")
            return

        parsed_target = urlparse(target_url)
        path_with_query = parsed_target.path
        if query:
            path_with_query += "?" + query

        logging.info(f"Forwarding {self.command} request to {target_url}")

        # Set up the connection to the target server
        connection = HTTPConnection(parsed_target.netloc, timeout=10)

        # Forward request headers and body
        headers = {key: value for key, value in self.headers.items() if key.lower() != "host"}
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else None

        try:
            # Forward the request to the target
            connection.request(self.command, path_with_query, body, headers)
            response = connection.getresponse()

            # Send response back to the client
            self.send_response(response.status)
            for header, value in response.getheaders():
                self.send_header(header, value)
            self._set_cors_headers()
            self.end_headers()

            # Stream response data
            while chunk := response.read(8192):
                self.wfile.write(chunk)
        except Exception as e:
            self.send_error(502, f"Error forwarding request: {str(e)}")
            logging.error(f"Error forwarding request: {e}")
        finally:
            connection.close()


if __name__ == "__main__":
    server_address = ("", 8080)  # Listen on all interfaces at port 8080
    httpd = HTTPServer(server_address, ProxyRequestHandler)
    logging.info("Proxy server is running on port 8080")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logging.info("Shutting down the server...")
        httpd.server_close()
