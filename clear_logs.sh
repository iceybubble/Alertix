#!/bin/bash

# Clear logs in local-log-agent/logs
echo "Clearing local-log-agent logs..."
find local-log-agent/logs -type f -name "*.jsonl" -exec truncate -s 0 {} \;

# Clear logs in siem-log-server/logs
echo "Clearing siem-log-server logs (JSONL and server.log)..."
find siem-log-server/logs -type f \( -name "*.jsonl" -o -name "server.log" \) -exec truncate -s 0 {} \;

echo "All logs cleared."
