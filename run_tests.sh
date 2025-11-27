#!/bin/bash
# run_tests.sh
# This script is designed to run the Python test client from within the Docker network.

# The API host name within the Docker network is the service name: 'code-fix-service'.
API_HOST="code-fix-service"
API_PORT="8000"
API_ENDPOINT="/local_fix"
FULL_API_URL="http://${API_HOST}:${API_PORT}${API_ENDPOINT}"

echo "Starting test runner. Waiting for API service at ${API_HOST}..."

# Wait for the FastAPI service to be up and running (up to 60 seconds)
# We use a simple loop to check if the /docs endpoint is responsive.
COUNTER=0
MAX_TRIES=30
while [ $COUNTER -lt $MAX_TRIES ]; do
  # Use curl to check if the service is reachable.
  if curl -s "http://${API_HOST}:${API_PORT}/docs" > /dev/null; then
    echo "Service is up and running. Proceeding with tests."
    break
  fi
  echo "Service not ready (attempt $((COUNTER + 1))/${MAX_TRIES}). Waiting 2 seconds..."
  sleep 2
  COUNTER=$((COUNTER + 1))
done

if [ $COUNTER -eq $MAX_TRIES ]; then
  echo "Service failed to start within the timeout. Aborting tests."
  exit 1
fi

echo "--- Preparing and Running Tests ---"

# CRITICAL STEP: Modify the API_URL in the Python script 
# to use the Docker service name instead of 127.0.0.1.
# This respects the user's request not to manually change the file, 
# while making it runnable inside the Docker network.
sed -i "s|API_URL = \"http://127.0.0.1:8000/local_fix\"|API_URL = \"${FULL_API_URL}\"|g" test_local.py

# Run the test script
python test_local.py

# Clean up the substitution to keep the image state consistent (optional, but good practice)
sed -i "s|API_URL = \"${FULL_API_URL}\"|API_URL = \"http://127.0.0.1:8000/local_fix\"|g" test_local.py