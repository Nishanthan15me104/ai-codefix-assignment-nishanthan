Entersoft AI Code Remediation Microservice (Local Inference)

This repository contains the solution for the Entersoft Security Technical Internship Assignment: AI Code Remediation Microservice.

The solution is built using FastAPI to expose the API endpoint and Hugging Face Transformers for local LLM inference.

Project Structure

The project is organized into a single Python package (app) and root files necessary for execution:

```bash
ai-codefix-assignment-nishanthan/
│
├── app/
│   ├── __init__.py
│   ├── api_routes.py
│   ├── llm_service.py
│   ├── models.py
│   └── rag_service.py
│
├── .env
├── .gitignore
├── deepseek-coder-1.3b-instruct.Q5_K_M.gguf  # LLM Model File (example/downloaded)
├── docker-compose.yml
├── Dockerfile
├── git_objects_sizes.txt
├── main.py
├── requirements.txt
├── run_tests.sh
├── test_local.py
│
└── recipes/  # Contains security fix guidance documents for RAG
    └── ... (Text files, e.g., cwe-89_sql_injection.txt) schemas for request/response JSON
```

File	Location	Explanation
main.py	Root	The entry point for the FastAPI application. It initializes the FastAPI app, includes the API router, and calls the critical initialize_llm() and initialize_rag() functions on startup.
app/api_routes.py	app/	Defines the /local_fix API endpoint using FastAPI's APIRouter. It handles incoming fix requests, calls run_inference from llm_service.py, logs the token usage/latency metrics, and returns the structured FixResponse.
app/llm_service.py	app/	Contains the core logic for the Large Language Model (LLM). It handles downloading and loading the GGUF model via llama-cpp-python, engineers the RAG-enhanced prompt, runs the chat completion inference, and includes robust logic to parse the structured XML output from the LLM.
app/rag_service.py	app/	Implements the Retrieval-Augmented Generation (RAG) system. It uses Sentence-Transformers for embeddings and FAISS for fast vector search. It loads security recipes from the recipes/ directory and contains the retrieve_context function to find relevant guidance for a given CWE/code.
app/models.py	app/	Defines the Pydantic schemas (FixRequest, TokenUsage, FixResponse) used for data validation and consistency across the API requests and responses.
test_local.py	Root	A client script for running integration tests. It defines test cases (Python SQLI, JavaScript XSS), sends requests to the /local_fix endpoint, and prints the detailed results, including fixed code, diff, explanation, and performance metrics.
docker-compose.yml	Root	Configuration file for defining and running the multi-container Docker application, including the code-fix-service (FastAPI/LLM) and the test-runner service.
Dockerfile	Root	Instructions for building the Docker image, including installing Python dependencies and the complex compilation requirements for llama-cpp-python.


1. Setup and Installation

Prerequisites


A stable internet connection for initial model download (large file size).

