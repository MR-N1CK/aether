import http.server
def run():
    server = http.server.HTTPServer(('127.0.0.1', 8080), http.server.SimpleHTTPRequestHandler)
