"""
Simple HTTP server to serve the frontend
Run: python server.py
Then open: http://localhost:8080
"""

import http.server
import socketserver
import os
from pathlib import Path

PORT = 8080
FRONTEND_DIR = os.path.dirname(os.path.abspath(__file__))

class FrontendHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Serve index.html for root path
        if self.path == '/':
            self.path = '/index.html'
        
        # Try to serve the file
        try:
            if self.path.endswith('.html'):
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                with open(os.path.join(FRONTEND_DIR, self.path[1:]), 'rb') as f:
                    self.wfile.write(f.read())
            elif self.path.endswith('.css'):
                self.send_response(200)
                self.send_header('Content-type', 'text/css')
                self.end_headers()
                with open(os.path.join(FRONTEND_DIR, self.path[1:]), 'rb') as f:
                    self.wfile.write(f.read())
            elif self.path.endswith('.js'):
                self.send_response(200)
                self.send_header('Content-type', 'application/javascript')
                self.end_headers()
                with open(os.path.join(FRONTEND_DIR, self.path[1:]), 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404)
        except Exception as e:
            self.send_error(404)
    
    def log_message(self, format, *args):
        # Custom logging
        print(f"[{self.log_date_time_string()}] {format % args}")

if __name__ == "__main__":
    handler = FrontendHandler
    
    with socketserver.TCPServer(("", PORT), handler) as httpd:
        print(f"\n{'='*60}")
        print(f"🌐 PhishGuard Frontend Server")
        print(f"{'='*60}")
        print(f"✓ Server running on http://localhost:{PORT}")
        print(f"✓ Open your browser and navigate to http://localhost:{PORT}")
        print(f"✓ Make sure the API is running: python backend/api.py")
        print(f"{'='*60}\n")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n✓ Server stopped")
