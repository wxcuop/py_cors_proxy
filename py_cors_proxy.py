import http.server
import http.client
from urllib.parse import urlparse, urljoin
import logging
import signal
import sys
import zlib
import json

# Configuration
MAX_REDIRECTS = 5  # Maximum number of redirects allowed
ENABLE_LOGGING = True  # Set to False to disable logging

# Feature configurations
CONFIG = {
    "originBlacklist": [],
    "originWhitelist": [],
    "checkRateLimit": None,
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
        """Forward the request to the target server or return a health check."""
        if self.path == "/favicon.ico":
            self.send_response(204)  # No Content
            self.end_headers()
            return 
        target_url = self.path.lstrip('/')
        
        # Health check: Return a 200 response if no target URL is provided
        if not target_url:
            self.send_response(200)
            self.add_cors_headers()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            health_check_response = {
                "status": "ok",
                "message": "CORS Proxy is running",
                "version": "1.0.0"
            }
            self.wfile.write(bytes(json.dumps(health_check_response), "utf-8"))
            if ENABLE_LOGGING:
                logger.info("Health check responded with status 200")
            return
    
        # Check for invalid URLs
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
    
        try:
            response = self.forward_request(target_url)
            self.send_response(response.status)
            for header, value in response.getheaders():
                if header.lower() not in ['content-length', 'transfer-encoding', 'connection']:
                    self.send_header(header, value)
            self.add_cors_headers()
            self.end_headers()
    
            # Stream the response body
            content_encoding = response.getheader('Content-Encoding', '')
            while chunk := response.read(8192):
                if content_encoding == 'gzip':
                    chunk = zlib.decompress(chunk, zlib.MAX_WBITS | 16)
                elif content_encoding == 'deflate':
                    chunk = zlib.decompress(chunk)
                self.wfile.write(chunk)
    
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

        if ENABLE_LOGGING:
            logger.info(f"Parsed URL: scheme={parsed_url.scheme}, netloc={parsed_url.netloc}, path={parsed_url.path}, query={parsed_url.query}")

        # Remove headers specified in configuration
        for header in CONFIG["removeHeaders"]:
            if header in self.headers:
                del self.headers[header]

        # Add headers specified in configuration
        headers = {key: value for key, value in self.headers.items()}
        headers.update(CONFIG["setHeaders"])

        # Set a default User-Agent if not present
        if 'User-Agent' not in headers:
            headers['User-Agent'] = (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                '(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            )

        # Ensure the Host header is set correctly
        headers['Host'] = parsed_url.netloc

        # Build the full path for the request
        full_path = parsed_url.path + ('?' + parsed_url.query if parsed_url.query else '')

        if ENABLE_LOGGING:
            logger.info(f"Forwarding request: method={self.command}, path={full_path}, headers={headers}")

        conn.request(self.command, full_path, headers=headers)
        response = conn.getresponse()

        # Handle redirects (301, 302, 303)
        if response.status in [301, 302, 303]:
            location = response.getheader('Location')
            if not location:
                raise Exception("Redirect without Location header")
            new_url = urljoin(url, location)
            return self.forward_request(new_url)

        return response

    def add_cors_headers(self):
        """Add CORS headers to the response."""
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', '*')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Access-Control-Allow-Credentials', 'true')
        if CONFIG["corsMaxAge"] > 0:
            self.send_header('Access-Control-Max-Age', str(CONFIG["corsMaxAge"]))
def run(server_class=http.server.HTTPServer, handler_class=CORSProxyHandler, port=8080, use_https=False):
    """
    Run the CORS proxy server.
    
    :param server_class: The server class to use.
    :param handler_class: The request handler class to use.
    :param port: The port number to start the server on.
    :param use_https: Whether to enable HTTPS.
    """
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)

    if use_https:
        import ssl
        # Create an SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # Load the certificate and private key
        cert_file = "cert.pem"  # Replace with the path to your certificate
        key_file = "key.pem"    # Replace with the path to your private key
        context.load_cert_chain(certfile=cert_file, keyfile=key_file)

        # Wrap the server's socket with the SSL context
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        protocol = "HTTPS"
    else:
        protocol = "HTTP"

    def signal_handler(sig, frame):
        print("\nShutting down the server...")
        httpd.server_close()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    print(f"Starting CORS Proxy on port {port} using {protocol}... Press Ctrl+C to stop.")
    if ENABLE_LOGGING:
        logger.info("CORS Proxy started on port %d using %s", port, protocol)
    httpd.serve_forever()

if __name__ == '__main__':
    run(use_https=False)
