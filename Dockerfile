# Use an official lightweight Python runtime as the base image
FROM python:3.11-slim

# Install necessary tools for the tests (curl for health check, bash)
# AND install build essentials (gcc, g++, cmake, etc.) for llama-cpp-python compilation
# NOTE: dos2unix is added here to fix line-ending issues for run_tests.sh
RUN apt-get update && apt-get install -y curl bash

# --- START OF FIX: Install Build Tools and dos2unix ---
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    cmake \
    build-essential \
    # Install dos2unix to ensure Unix-style (LF) line endings for shell scripts
    dos2unix \ 
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
# --- END OF FIX ---

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY main.py .
COPY app ./app
COPY recipes ./recipes

# Copy the test runner script and the test client
COPY run_tests.sh .
COPY test_local.py .

# 1. Ensure the script is executable
RUN chmod +x run_tests.sh

# 2. CRITICAL FIX: Convert Windows (CRLF) line endings to Linux (LF) for the shell script
RUN dos2unix run_tests.sh

# Expose the port that Uvicorn will run on
EXPOSE 8000

# Command to run the main application using Uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]