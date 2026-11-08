#!/bin/bash
# Rotate application logs weekly and compress old generations.
LOG_DIR="/var/log/myapp"
find "$LOG_DIR" -name "*.log" -mtime +7 -exec gzip -9 {} \;
find "$LOG_DIR" -name "*.log.gz" -mtime +90 -delete
systemctl reload myapp 2>/dev/null || true
