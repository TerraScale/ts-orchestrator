from http.server import BaseHTTPRequestHandler, HTTPServer


class Metadata(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"instance")


server = HTTPServer(("169.254.169.254", 80), Metadata)
print("ready", flush=True)
server.serve_forever()
