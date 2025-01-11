### **Key Features**

1\. **CORS Headers**:

   - Adds `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, and other necessary headers.

   - Handles preflight (`OPTIONS`) requests.

2\. **Request Forwarding**:

   - Forwards `GET` and `POST` requests to the target server.

   - Strips unwanted headers (e.g., cookies) and adds custom headers.

3\. **Origin Validation**:

   - Supports whitelisting and blacklisting of origins.

4\. **Hostname Validation**:

   - Ensures only valid hostnames or IPs are proxied.

5\. **Error Handling**:

   - Returns appropriate HTTP error codes for invalid requests or server errors.

6\. **how to use**:

   - Access the proxy at `http://localhost:8080/<target_url>`.
