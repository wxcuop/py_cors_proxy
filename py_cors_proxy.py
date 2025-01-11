import http.server
import http.client
from urllib.parse import urlparse, urljoin
import logging
import signal
import sys

# Configuration
MAX_REDIRECTS = 5  # Maximum number of redirects allowed
ENABLE_LOGGING = True  # Set to False to disable logging

# Configure logging
if ENABLE_LOGGING:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
logger = logging.getLogger(__name__)


class CORSProxyHandler(http.server.BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        """Handle preflight (OPTIONS) requests."""
        if ENABLE_LOGGING:
            logger.info(f"OPTIONS request received for {self.path}")
        self.send_response(200)
        self.add_cors_headers()
        self.end_headers()

    def do_GET(self):
        """Handle GET requests."""
        if ENABLE_LOGGING:
            logger.info(f"GET request received for {self.path}")
        self.proxy_request()

    def do_POST(self):
        """Handle POST requests."""
        if ENABLE_LOGGING:
            logger.info(f"POST request received for {self.path}")
        self.proxy_request()

    def proxy_request(self):
        """Forward the request to the target server."""
        target_url = self.path[1:]  # Remove leading '/'
        if not target_url.startswith(('http://', 'https://')):
            self.send_error(400, "Invalid URL")
            if ENABLE_LOGGING:
                logger.error(f"Invalid URL: {target_url}")
            return

        try:
            response = self.forward_request(target_url)
            self.send_response(response.status)
            for header, value in response.getheaders():
                if header.lower() not in ['content-length', 'transfer-encoding', 'connection']:
                    self.send_header(header, value)
            self.add_cors_headers()
            self.end_headers()
            self.wfile.write(response.read())
            if ENABLE_LOGGING:
                logger.info(f"Response forwarded with status {response.status} for {target_url}")
        except Exception as e:
            self.send_error(500, f"Error: {str(e)}")
            if ENABLE_LOGGING:
                logger.error(f"Error while processing request for {target_url}: {str(e)}")

    def forward_request(self, url, redirect_count=0):
        """Forwards the request to the target server, handling redirects."""
        if redirect_count > MAX_REDIRECTS:
            raise Exception("Too many redirects")

        parsed_url = urlparse(url)
        connection_class = http.client.HTTPSConnection if parsed_url.scheme == 'https' else http.client.HTTPConnection
        conn = connection_class(parsed_url.netloc)

        # Forward headers
        headers = {key: value for key, value in self.headers.items() if key.lower() not in ['host']}
        conn.request(self.command, parsed_url.path + ('?' + parsed_url.query if parsed_url.query else ''), headers=headers)

        response = conn.getresponse()

        # Handle redirects (301, 302, 303, 307, 308)
        if response.status in [301, 302, 303, 307, 308]:
            location = response.getheader('Location')
            if not location:
                raise Exception("Redirect without Location header")
            new_url = urljoin(url, location)  # Resolve relative redirects
            if ENABLE_LOGGING:
                logger.info(f"Redirecting to {new_url} (status: {response.status})")
            return self.forward_request(new_url, redirect_count + 1)

        return response

    def add_cors_headers(self):
        """Add CORS headers to the response."""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Access-Control-Expose-Headers', '*')


def run(server_class=http.server.HTTPServer, handler_class=CORSProxyHandler, port=8080):
    """Run the CORS proxy server."""
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)

    # Gracefully handle Ctrl+C
    def signal_handler(sig, frame):
        print("\nShutting down the server...")
        httpd.server_close()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    print(f"Starting CORS Proxy on port {port}... Press Ctrl+C to stop.")
    if ENABLE_LOGGING:
        logger.info("CORS Proxy started on port %d", port)
    httpd.serve_forever()


if __name__ == '__main__':
    run()
