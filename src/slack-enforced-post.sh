#!/bin/bash
# slack-enforced-post.sh - Deterministic Block Kit enforcement wrapper
# Usage: slack-enforced-post.sh <channel_id> <payload_file_or_json_string>
# 
# DETERMINISTIC VALIDATION:
# - Rejects non-Block Kit payloads (enforces infrastructure-level formatting)
# - Validates rich_text blocks structure
# - Blocks em dashes and bare markdown patterns
# - Logs all attempts for auditing

set -euo pipefail

CHANNEL="$1"
PAYLOAD_INPUT="$2"
SECURITY_DIR="/root/.openclaw/workspace/security"
LOG_FILE="${SECURITY_DIR}/enforcement-log.jsonl"

# Ensure log directory exists
mkdir -p "$SECURITY_DIR"

# Get timestamp for logging
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")

# Function to log attempts
log_attempt() {
    local status="$1"
    local reason="$2"
    local payload_preview="${3:-}"
    
    echo "$(cat <<EOF
{
  "timestamp": "$TIMESTAMP",
  "channel": "$CHANNEL",
  "status": "$status",
  "reason": "$reason",
  "payload_preview": "${payload_preview:0:200}"
}
EOF
)" >> "$LOG_FILE"
}

# Function to validate payload structure
validate_payload() {
    local payload="$1"
    
    # Must be valid JSON
    if ! echo "$payload" | jq . >/dev/null 2>&1; then
        log_attempt "REJECT" "Invalid JSON" "$payload"
        echo "ERROR: Payload is not valid JSON" >&2
        return 1
    fi
    
    # Must contain blocks array
    if ! echo "$payload" | jq '.blocks' >/dev/null 2>&1; then
        log_attempt "REJECT" "Missing blocks array" "$payload"
        echo "ERROR: Payload must contain 'blocks' array for Block Kit" >&2
        return 1
    fi
    
    # Must have at least one block
    local block_count=$(echo "$payload" | jq '.blocks | length')
    if [ "$block_count" -eq 0 ]; then
        log_attempt "REJECT" "Empty blocks array" "$payload"
        echo "ERROR: Blocks array cannot be empty" >&2
        return 1
    fi
    
    # Must contain rich_text blocks
    local rich_text_count=$(echo "$payload" | jq '[.blocks[] | select(.type == "rich_text")] | length')
    if [ "$rich_text_count" -eq 0 ]; then
        log_attempt "REJECT" "No rich_text blocks found" "$payload"
        echo "ERROR: Payload must contain at least one rich_text block" >&2
        return 1
    fi
    
    # Check for em dashes in text content
    if echo "$payload" | jq -r '.. | select(type == "string")' | grep -q '—'; then
        log_attempt "REJECT" "Em dashes found in text content" "$payload"
        echo "ERROR: Em dashes (—) are not allowed. Use regular dashes (-) instead." >&2
        return 1
    fi
    
    # Check for bare markdown patterns in text elements
    local text_content=$(echo "$payload" | jq -r '.. | select(type == "object" and has("type") and .type == "text") | .text // empty')
    
    # Check for **bold** patterns
    if echo "$text_content" | grep -qE '\*\*[^*]+\*\*'; then
        log_attempt "REJECT" "Bare markdown **bold** pattern found" "$payload"
        echo "ERROR: Bare markdown **bold** patterns not allowed. Use style: {\"bold\": true} instead." >&2
        return 1
    fi
    
    # Check for [text](url) patterns
    if echo "$text_content" | grep -qE '\[[^\]]+\]\([^)]+\)'; then
        log_attempt "REJECT" "Bare markdown link pattern found" "$payload"
        echo "ERROR: Bare markdown [text](url) patterns not allowed. Use link elements instead." >&2
        return 1
    fi
    
    # Check for *italic* patterns (single asterisk)
    if echo "$text_content" | grep -qE '\*[^*\s][^*]*[^*\s]\*'; then
        log_attempt "REJECT" "Bare markdown *italic* pattern found" "$payload"
        echo "ERROR: Bare markdown *italic* patterns not allowed. Use style: {\"italic\": true} instead." >&2
        return 1
    fi
    
    return 0
}

# Main execution
if [ -z "$CHANNEL" ] || [ -z "$PAYLOAD_INPUT" ]; then
    echo "Usage: slack-enforced-post.sh <channel_id> <payload_file_or_json_string>" >&2
    exit 1
fi

# Get payload content
if [ -f "$PAYLOAD_INPUT" ]; then
    PAYLOAD=$(cat "$PAYLOAD_INPUT")
else
    PAYLOAD="$PAYLOAD_INPUT"
fi

# Validate payload
if ! validate_payload "$PAYLOAD"; then
    exit 1
fi

# Add channel to payload if not present
FINAL_PAYLOAD=$(echo "$PAYLOAD" | jq --arg channel "$CHANNEL" '. + {channel: $channel}')

# Get bot token from openclaw.json
TOKEN=$(jq -r '.channels.slack.botToken' /root/.openclaw/openclaw.json)

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    log_attempt "ERROR" "Could not find Slack bot token" "$FINAL_PAYLOAD"
    echo "ERROR: Could not find Slack bot token in openclaw.json" >&2
    exit 1
fi

# Post to Slack API
RESPONSE=$(curl -s -X POST "https://slack.com/api/chat.postMessage" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json; charset=utf-8" \
    -d "$FINAL_PAYLOAD")

# Check response
if echo "$RESPONSE" | jq -e '.ok' >/dev/null; then
    TS=$(echo "$RESPONSE" | jq -r '.ts')
    log_attempt "SUCCESS" "Message posted successfully" "$FINAL_PAYLOAD"
    echo "Message posted to $CHANNEL (ts: $TS)"
else
    ERROR=$(echo "$RESPONSE" | jq -r '.error // "unknown error"')
    log_attempt "API_ERROR" "Slack API error: $ERROR" "$FINAL_PAYLOAD"
    echo "ERROR: Slack API error: $ERROR" >&2
    exit 1
fi