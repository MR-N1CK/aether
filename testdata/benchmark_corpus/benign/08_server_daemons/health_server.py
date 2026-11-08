#!/usr/bin/env python3
"""Local health endpoint for the load balancer's uptime probes."""
import json
import socket

HOST, PORT = "127.0.0.1", 8080

def build_status():
    return json.dumps({"status": "ok", "uptime_seconds": 4211})

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(5)
while True:
    conn, _ = server.accept()
    with conn:
        conn.sendall(build_status().encode())
