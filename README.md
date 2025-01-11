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

How to Configure
----------------

Modify the `CONFIG` dictionary at the top of the script to enable or customize each feature.
Example configuration:

python

`CONFIG =  {    
"originBlacklist":  ["http://blocked-origin.com"],
"originWhitelist":  ["http://allowed-origin.com"],    
"checkRateLimit":  lambda origin:  "Too many requests"  if origin ==  "http://rate-limited.com"  else  None,    
"redirectSameOrigin":  True,
"requireHeader":  ["X-Custom-Header"],
"removeHeaders":  ["X-Remove-This"],
"setHeaders":  {"X-Added-Header":  "Value"},
"corsMaxAge":  3600,  }`
