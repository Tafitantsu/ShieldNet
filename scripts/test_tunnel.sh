#!/bin/bash

set -e # Exit immediately if a command exits with a non-zero status.
# set -x # Print commands and their arguments as they are executed (for debugging).

COMPOSE_FILE="../docker-compose.yml" # Adjust if your script is elsewhere
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)" # Assumes scripts/ is one level down from project root

# Ensure docker-compose is available
if ! command -v docker-compose &> /dev/null
then
    echo "docker-compose could not be found. Please install it."
    exit 1
fi

# Ensure we are in the project root for docker-compose contexts
cd "$PROJECT_ROOT"

cleanup() {
    echo "Cleaning up Docker services..."
    docker-compose -f "$COMPOSE_FILE" down -v --remove-orphans
    echo "Cleanup finished."
}

# Trap EXIT signal to ensure cleanup runs
# trap cleanup EXIT # Disabled by default to allow inspection after script run. Uncomment to auto-cleanup.

echo "Starting Docker services in detached mode..."
# Use --build to ensure images are up-to-date if Dockerfiles changed
docker-compose -f "$COMPOSE_FILE" up --build -d

echo "Waiting for services to initialize (e.g., server to start listening)..."
# This is a simple sleep. A more robust solution would poll health checks or logs.
# The client also has reconnection logic which might make this less critical.
sleep 15 # Increased wait time for services to stabilize

# Test data
TEST_MESSAGE="Hello, secure tunnel world! $(date)"
EXPECTED_RESPONSE="$TEST_MESSAGE" # echo-server should echo the message

echo "Sending test message: '$TEST_MESSAGE'"

# Use netcat (nc) to send data to the tunnel client's exposed port (1080)
# and capture the response.
# The timeout for nc is important to prevent hanging if something is wrong.
# macOS netcat is different from GNU netcat.
# For GNU netcat: nc -w 5 localhost 1080
# For macOS netcat (or BSD): nc -G 5 localhost 1080
# Using a simple echo piped to nc which closes the write side.
ACTUAL_RESPONSE=""
NC_TIMEOUT=10 # seconds

if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS/BSD netcat
    # It might not print to stdout if connection closes too fast or no data from server.
    # This is a common issue with scripting nc for request-response.
    # Using socat might be more reliable if available, or a small Python script.
    # Let's try with a simple echo and hope for the best with nc.
    # We'll use a subshell to manage the timeout for the read part.
    echo "Using macOS/BSD netcat variant."
    TEMP_RESPONSE_FILE=$(mktemp)
    if ! ACTUAL_RESPONSE=$( (echo "$TEST_MESSAGE"; sleep 1) | nc -v -w $NC_TIMEOUT localhost 1080 2> "$TEMP_RESPONSE_FILE"); then
        echo "Netcat command failed or timed out (macOS)."
        cat "$TEMP_RESPONSE_FILE"
        rm "$TEMP_RESPONSE_FILE"
        # cleanup # Perform cleanup on failure
        exit 1
    fi
    # Check TEMP_RESPONSE_FILE for errors if ACTUAL_RESPONSE is empty but command succeeded
    if [[ -z "$ACTUAL_RESPONSE" ]] && grep -q "Connection refused" "$TEMP_RESPONSE_FILE"; then
        echo "Netcat reported Connection Refused (macOS)."
        cat "$TEMP_RESPONSE_FILE"
        rm "$TEMP_RESPONSE_FILE"
        # cleanup
        exit 1
    fi
    rm "$TEMP_RESPONSE_FILE"
else
    # Assuming GNU netcat
    echo "Using GNU netcat variant."
    if ! ACTUAL_RESPONSE=$(echo "$TEST_MESSAGE" | nc -w $NC_TIMEOUT localhost 1080); then
        echo "Netcat command failed or timed out (GNU)."
        # cleanup
        exit 1
    fi
fi


echo "Received response: '$ACTUAL_RESPONSE'"

# Verify the response
if [ "$ACTUAL_RESPONSE" == "$EXPECTED_RESPONSE" ]; then
    echo "SUCCESS: Tunnel test passed! Received data matches sent data."
else
    echo "FAILURE: Tunnel test failed. Received data does not match sent data."
    echo "Expected: '$EXPECTED_RESPONSE'"
    echo "Actual:   '$ACTUAL_RESPONSE'"
    # cleanup # Perform cleanup on failure
    exit 1
fi

echo "Test finished. You may want to run 'docker-compose -f $COMPOSE_FILE down' manually to stop services."
# Or uncomment 'trap cleanup EXIT' at the top for automatic cleanup.

exit 0
