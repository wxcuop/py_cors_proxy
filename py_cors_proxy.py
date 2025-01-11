import http.server
import urllib.request
from urllib.parse import urlparse, urljoin

MAX_REDIRECTS = 5  # Maximum number of redirects allowed

class RedirectHandlingProxy(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def handle_request(self):
        """Handles incoming requests and forwards them to the target server."""
        target_url = self.path[1:]  # Remove leading '/'
        if not target_url.startswith(('http://', 'https://')):
            self.send_error(400, "Invalid URL")
            return

        try:
            response = self.forward_request(target_url)
            self.send_response(response.status)
            for header, value in response.getheaders():
                if header.lower() not in ['content-length', 'transfer-encoding', 'connection']:
                    self.send_header(header, value)
            self.end_headers()
            self.wfile.write(response.read())
        except Exception as e:
            self.send_error(500, f"Error: {str(e)}")

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
            return self.forward_request(new_url, redirect_count + 1)

        return response


def run(server_class=http.server.HTTPServer, handler_class=RedirectHandlingProxy, port=8080):
    """Run the CORS proxy server."""
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting CORS Proxy on port {port}...")
    httpd.serve_forever()


if __name__ == '__main__':
    run()
