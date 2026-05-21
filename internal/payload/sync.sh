#!/bin/bash
# Sync payload templates from project root to internal/payload
cp "$(dirname "$0")/../../payload/tunnel.php" "$(dirname "$0")/"
cp "$(dirname "$0")/../../payload/tunnel.jsp" "$(dirname "$0")/"
echo "payload templates synced"
