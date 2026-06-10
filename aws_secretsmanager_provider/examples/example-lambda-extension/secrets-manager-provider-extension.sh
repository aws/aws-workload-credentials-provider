#!/bin/bash

set -euo pipefail

OWN_FILENAME="$(basename $0)"
LAMBDA_EXTENSION_NAME="$OWN_FILENAME" # (external) extension name has to match the filename
TMPFILE=/tmp/$OWN_FILENAME

# Graceful Shutdown
_term() {
  echo "[${LAMBDA_EXTENSION_NAME}] Received EXIT"
  # forward EXIT to child procs and exit
  kill -TERM "$PID" 2>/dev/null
  echo "[${LAMBDA_EXTENSION_NAME}] Exiting"
  exit 0
}

forward_exit_and_wait() {
  trap _term EXIT
  wait "$PID"
  trap - EXIT
}

start_provider() {
  if [ -z "${PROVIDER_PID:-}" ]; then
    echo "[${LAMBDA_EXTENSION_NAME}] Starting Secrets Manager Provider."
    # Switching working directory to ensure that the logs are written to a folder that has write permissions.
    (cd /tmp && /opt/bin/aws-workload-credentials-provider sm start &)
    PROVIDER_PID=$!

    echo "[${LAMBDA_EXTENSION_NAME}] Checking if the Provider is serving requests."
    RETRIES=0
    MAX_RETRIES=200
    while true; do
      RESPONSE=$(curl -s http://localhost:2773/ping || echo "Provider has not started yet.")
      if [ "$RESPONSE" = "healthy" ]; then
        echo "[${LAMBDA_EXTENSION_NAME}] Provider has started."
        break
      else
        if [ $RETRIES -ge $MAX_RETRIES ]; then
          echo "[${LAMBDA_EXTENSION_NAME}] Provider failed to start after $MAX_RETRIES retries."
          exit 1
        fi
        echo "[${LAMBDA_EXTENSION_NAME}] Provider has not started yet, retrying in 100 milliseconds..."
        sleep 0.1 # Sleep for 100 milliseconds
      fi
    done
  else
    echo "[${LAMBDA_EXTENSION_NAME}] Provider already started, ignoring INVOKE event."
  fi
}


stop_provider() {
  if [ -n "$PROVIDER_PID" ]; then
    echo "[${LAMBDA_EXTENSION_NAME}] Stopping the Secrets Manager Provider."
    kill "$PROVIDER_PID" 2>/dev/null
    unset PROVIDER_PID
  else
    echo "[${LAMBDA_EXTENSION_NAME}] Provider not running. Nothing to stop."
  fi
}


# Initialization
# To run any extension processes that need to start before the runtime initializes, run them before the /register
echo "[${LAMBDA_EXTENSION_NAME}] Initialization"

# Registration
# The extension registration also signals to Lambda to start initializing the runtime.
HEADERS="$(mktemp)"
echo "[${LAMBDA_EXTENSION_NAME}] Registering at http://${AWS_LAMBDA_RUNTIME_API}/2020-01-01/extension/register"
curl -sS -LD "$HEADERS" -XPOST "http://${AWS_LAMBDA_RUNTIME_API}/2020-01-01/extension/register" --header "Lambda-Extension-Name: ${LAMBDA_EXTENSION_NAME}" -d "{ \"events\": [\"INVOKE\", \"SHUTDOWN\"]}" > $TMPFILE

RESPONSE=$(<$TMPFILE)
HEADINFO=$(<$HEADERS)
# Extract Extension ID from response headers
EXTENSION_ID=$(grep -Fi Lambda-Extension-Identifier "$HEADERS" | tr -d '[:space:]' | cut -d: -f2)
echo "[${LAMBDA_EXTENSION_NAME}] Registration response: ${RESPONSE} with EXTENSION_ID  ${EXTENSION_ID}"

# Event processing
# Continuous loop to wait for events from Extensions API
while true
do
  echo "[${LAMBDA_EXTENSION_NAME}] Waiting for event. Get /next event from http://${AWS_LAMBDA_RUNTIME_API}/2020-01-01/extension/event/next"

  # Get an event. The HTTP request will block until one is received
  curl -sS -L -XGET "http://${AWS_LAMBDA_RUNTIME_API}/2020-01-01/extension/event/next" --header "Lambda-Extension-Identifier: ${EXTENSION_ID}" > $TMPFILE &
  PID=$!
  forward_exit_and_wait

  EVENT_DATA=$(<$TMPFILE)
  if [[ $EVENT_DATA == *"INVOKE"* ]]; then
    echo "[extension: ${LAMBDA_EXTENSION_NAME}] Received INVOKE event."

    # Starting the Secrets Manager Provider
    # The provider is initialized AFTER the first Invoke phase, instead of right AFTER Init phase.
    # This prevents users from calling for secrets before the Init phase has finished.
    # Initializing the provider during Init would allow users to call and cache secrets before the snapshot phase (occurs last in Init), which in turn could store those values
    # in a snapshot of the sandbox for up to 14 days. https://docs.aws.amazon.com/lambda/latest/dg/snapstart.html
    # Implement retry logic in your application code, to accommodate delays in provider initialization.
    start_provider
  fi

  if [[ $EVENT_DATA == *"SHUTDOWN"* ]]; then
    echo "[extension: ${LAMBDA_EXTENSION_NAME}] Received SHUTDOWN event. Exiting."
    stop_provider
    exit 0 # Exit if we receive a SHUTDOWN event
  fi

done
