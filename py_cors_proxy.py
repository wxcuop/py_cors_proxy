import http.server
import http.client
from urllib.parse import urlparse, urljoin
import logging
import signal
import sys
import zlib
import json
from collections import defaultdict
import time

# Configuration
MAX_REDIRECTS = 5  # Maximum number of redirects allowed
ENABLE_LOGGING = True  # Set to False to disable logging
RATE_LIMIT_WINDOW = 60  # Rate limit window in seconds
RATE_LIMIT_MAX_REQUESTS = 100  # Max requests per origin per window

# Feature configurations
CONFIG = {
    "originBlacklist": [],
    "originWhitelist": [],
    "checkRateLimit": defaultdict(lambda: {"count": 0, "start_time": time.time()}),
    "redirectSameOrigin": False,
    "requireHeader": None,
    "removeHeaders": [],
    "setHeaders": {},
    "corsMaxAge": 3600,  # Set Access-Control-Max-Age to 1 hour
}

# Configure logging
if ENABLE_LOGGING:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
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
        """Forward the request to the target server or return a health check."""
        if self.path == "/favicon.ico":
            self.send_response(204)  # No Content
            self.end_headers()
            return
        target_url = self.path.lstrip("/")

        # Health check: Return a 200 response if no target URL is provided
        if not target_url:
            self.send_response(200)
            self.add_cors_headers()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            health_check_response = {
                "status": "ok",
                "message": "CORS Proxy is running",
                "version": "1.0.0",
            }
            self.wfile.write(bytes(json.dumps(health_check_response), "utf-8"))
            if ENABLE_LOGGING:
                logger.info("Health check responded with status 200")
            return

        # Check for invalid URLs
        if not target_url.startswith(("http://", "https://")):
            self.send_error(400, "Invalid URL")
            if ENABLE_LOGGING:
                logger.error(f"Invalid URL: {target_url}")
            return

        origin = self.headers.get("Origin", "")

        # Rate limiting
        if not self.rate_limit_check(origin):
            self.send_error(429, "Too Many Requests")
            if ENABLE_LOGGING:
                logger.warning(f"Rate limit exceeded for origin: {origin}")
            return

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

        try:
            response = self.forward_request(target_url)
            self.send_response(response.status)

            # Add response headers, excluding sensitive ones
            for header, value in response.getheaders():
                if header.lower() not in ["set-cookie", "set-cookie2"]:
                    self.send_header(header, value)

            self.add_cors_headers()
            self.add_expose_headers(response)
            self.end_headers()

            # Stream the response body
            content_encoding = response.getheader("Content-Encoding", "")
            while chunk := response.read(8192):
                if content_encoding == "gzip":
                    chunk = zlib.decompress(chunk, zlib.MAX_WBITS | 16)
                elif content_encoding == "deflate":
                    chunk = zlib.decompress(chunk)
                self.wfile.write(chunk)

            if ENABLE_LOGGING:
                logger.info(f"Response forwarded with status {response.status} for {target_url}")
        except Exception as e:
            self.send_error(500, f"Error: {str(e)}")
            if ENABLE_LOGGING:
                logger.error(f"Error while processing request for {target_url}: {str(e)}")

    def forward_request(self, url):
        """Forwards the request to the target server, handling redirects."""
        parsed_url = urlparse(url)
        connection_class = (
            http.client.HTTPSConnection if parsed_url.scheme == "https" else http.client.HTTPConnection
        )
        conn = connection_class(parsed_url.netloc)

        if ENABLE_LOGGING:
            logger.info(
                f"Parsed URL: scheme={parsed_url.scheme}, netloc={parsed_url.netloc}, path={parsed_url.path}, query={parsed_url.query}"
            )

        # Remove and add headers based on configuration
        headers = {key: value for key, value in self.headers.items()}
        for header in CONFIG["removeHeaders"]:
            headers.pop(header, None)
        headers.update(CONFIG["setHeaders"])

        # Ensure the Host header is set correctly
        headers["Host"] = parsed_url.netloc

        # Build the full path for the request
        full_path = parsed_url.path + ("?" + parsed_url.query if parsed_url.query else "")

        conn.request(self.command, full_path, headers=headers)
        response = conn.getresponse()

        # Handle redirects (301, 302, 303, 307, 308)
        if response.status in [301, 302, 303, 307, 308]:
            location = response.getheader("Location")
            if not location:
                raise Exception("Redirect without Location header")
            new_url = urljoin(url, location)

            # Modify headers for GET requests
            if response.status in [301, 302, 303]:
                self.command = "GET"
                headers["Content-Length"] = "0"
                headers.pop("Content-Type", None)

            if ENABLE_LOGGING:
                logger.info(f"Redirecting to {new_url} with updated headers.")
            return self.forward_request(new_url)

        return response

    def add_cors_headers(self):
        """Add CORS headers to the response."""
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Credentials", "true")
        if CONFIG["corsMaxAge"] > 0:
            self.send_header("Access-Control-Max-Age", str(CONFIG["corsMaxAge"]))

    def add_expose_headers(self, response):
        """Dynamically add Access-Control-Expose-Headers based on response headers."""
        exposed_headers = ", ".join(header for header in response.getheaders())
        self.send_header("Access-Control-Expose-Headers", exposed_headers)

    def rate_limit_check(self, origin):
        """Check if the origin is exceeding the rate limit."""
        now = time.time()
        rate_limit_data = CONFIG["checkRateLimit"][origin]

        if now - rate_limit_data["start_time"] > RATE_LIMIT_WINDOW:
            # Reset the rate limit window
            CONFIG["checkRateLimit"][origin] = {"count": 1, "start_time": now}
            return True

        if rate_limit_data["count"] < RATE_LIMIT_MAX_REQUESTS:
            # Increment the request count
            rate_limit_data["count"] += 1
            return True

        return False


def run(server_class=http.server.HTTPServer, handler_class=CORSProxyHandler, port=8080, use_https=False):
    """Run the CORS proxy server."""
    server_address = ("", port)
    httpd = server_class(server_address, handler_class)

    print(f"Starting CORS Proxy on port {port}... Press Ctrl+C to stop.")
    if ENABLE_LOGGING:
        logger.info("CORS Proxy started on port %d", port)

    httpd.serve_forever()


if __name__ == "__main__":
    run()
