# Use an official lightweight Python runtime as the base image
FROM python:3.11-slim

# Install necessary tools for the tests (curl for health check, bash)
# AND install build essentials (gcc, g++, cmake, etc.) for llama-cpp-python compilation
RUN apt-get update && apt-get install -y curl bash

# --- START OF FIX: Install Build Tools ---
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    cmake \
    build-essential \
    # Ensure any CUDA-related compilation dependencies are met (for llama-cpp-python)
    # The default build usually targets CPU, but these ensure the environment is complete.
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
RUN chmod +x run_tests.sh

# Expose the port that Uvicorn will run on
EXPOSE 8000

# Command to run the main application using Uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]