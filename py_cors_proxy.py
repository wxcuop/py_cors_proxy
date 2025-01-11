import http.server
import http.client
from urllib.parse import urlparse, urljoin
import logging
import signal
import sys

# Configuration
MAX_REDIRECTS = 5  # Maximum number of redirects allowed
ENABLE_LOGGING = True  # Set to False to disable logging

# Feature configurations
CONFIG = {
    "originBlacklist": [],           # Requests from these origins will be blocked.
    "originWhitelist": [],           # If non-empty, requests not from an origin in this list will be blocked.
    "checkRateLimit": None,          # Function that may enforce a rate-limit by returning a non-empty string.
    "redirectSameOrigin": False,     # Redirect the client to the requested URL for same-origin requests.
    "requireHeader": None,           # Require a header to be set?
    "removeHeaders": [],             # Strip these request headers.
    "setHeaders": {},                # Set these request headers.
    "corsMaxAge": 0,                 # Access-Control-Max-Age header value (in seconds).
}

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

        origin = self.headers.get('Origin', '')

        # Origin blacklist check
        if origin in CONFIG["originBlacklist"]:
            self.send_error(403, f"The origin '{origin}' is blacklisted.")
            if ENABLE_LOGGING:
                logger.warning(f"Blocked blacklisted origin: {origin}")
            return

        # Origin whitelist check
        if CONFIG["originWhitelist"] and origin not in CONFIG["originWhitelist"]:
            self.send_error(403, f"The origin '{origin}' is not whitelisted.")
            if ENABLE_LOGGING:
                logger.warning(f"Blocked non-whitelisted origin: {origin}")
            return

        # Rate limit check
        if CONFIG["checkRateLimit"]:
            rate_limit_message = CONFIG["checkRateLimit"](origin)
            if rate_limit_message:
                self.send_error(429, f"Rate limit exceeded: {rate_limit_message}")
                if ENABLE_LOGGING:
                    logger.warning(f"Rate limit exceeded for origin: {origin}")
                return

        try:
            response = self.forward_request(target_url, origin)
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

    def forward_request(self, url, origin=None):
        """Forwards the request to the target server, handling redirects."""
        parsed_url = urlparse(url)
        connection_class = http.client.HTTPSConnection if parsed_url.scheme == 'https' else http.client.HTTPConnection
        conn = connection_class(parsed_url.netloc)

        # Remove headers specified in configuration
        for header in CONFIG["removeHeaders"]:
            if header in self.headers:
                del self.headers[header]

        # Add headers specified in configuration
        headers = {key: value for key, value in self.headers.items()}
        headers.update(CONFIG["setHeaders"])

        conn.request(self.command, parsed_url.path + ('?' + parsed_url.query if parsed_url.query else ''), headers=headers)

        response = conn.getresponse()

        # Handle redirects (301, 302, 303)
        if response.status in [301, 302, 303]:
            location = response.getheader('Location')
            if not location:
                raise Exception("Redirect without Location header")
            new_url = urljoin(url, location)  # Resolve relative redirects

            if CONFIG["redirectSameOrigin"] and origin and new_url.startswith(origin):
                self.send_response(301)
                self.send_header('Location', new_url)
                self.end_headers()
                return None

            return self.forward_request(new_url)

        return response

    def add_cors_headers(self):
        """Add CORS headers to the response."""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        
        if CONFIG["corsMaxAge"] > 0:
            self.send_header('Access-Control-Max-Age', str(CONFIG["corsMaxAge"]))

def run(server_class=http.server.HTTPServer, handler_class=CORSProxyHandler, port=8080):
    """Run the CORS proxy server."""
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)

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
