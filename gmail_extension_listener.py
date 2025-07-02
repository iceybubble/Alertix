import http.server
import socketserver
import json
import requests

PORT = 9999
SIEM_ENDPOINT = "http://localhost:5000/log"

class GmailEventHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/gmail-event':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            try:
                data = json.loads(post_data.decode('utf-8'))
                log_message = data.get("event", "Unknown Gmail event")
                log_entry = {
                    "log": log_message,
                    "level": "INFO",
                    "user_agent": "Gmail-Extension",
                }
                requests.post(SIEM_ENDPOINT, json=log_entry)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(f"Error: {e}".encode())

if __name__ == "__main__":
    print(f"Gmail listener running on http://localhost:{PORT}")
    with socketserver.TCPServer(("", PORT), GmailEventHandler) as httpd:
        httpd.serve_forever()
