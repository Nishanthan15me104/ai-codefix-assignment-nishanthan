Entersoft AI Code Remediation Microservice (Local Inference)

This repository contains the solution for the Entersoft Security Technical Internship Assignment: AI Code Remediation Microservice.

The solution is built using FastAPI to expose the API endpoint and Hugging Face Transformers for local LLM inference.

Project Structure

The project is organized into a single Python package (app) and root files necessary for execution:

.
├── main.py             # Entry point (FastAPI App initialization)
├── requirements.txt    # Project dependencies
├── test_local.py       # Developer utility for local testing
└── app/
    ├── __init__.py     # Marks 'app' as a Python package
    ├── api_routes.py   # Defines the POST /local_fix endpoint
    ├── llm_service.py  # Handles LLM loading, prompting, and inference
    └── models.py       # Pydantic schemas for request/response JSON


1. Setup and Installation

Prerequisites

Python 3.10+

A stable internet connection for initial model download (large file size).

Step-by-Step Guide

Create and Activate Virtual Environment:

python -m venv .venv
# On Windows:
.\.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate


Install Dependencies:

pip install -r requirements.txt


Start the Microservice:
The service will automatically download and load the LLM during startup. This step might take several minutes the first time as the model weights are fetched.

uvicorn main:app --reload


(The service will be available at http://127.0.0.1:8000)

2. Local Model Inference

Model Used

Feature

Details

Model Name

Qwen/Qwen2.5-1.5B-Instruct

Model Size

1.5 Billion Parameters

Inference Library

Hugging Face transformers (AutoModelForCausalLM)

Device Mapping

Configured for CPU (device_map="cpu") for maximum compatibility, as requested by the assignment.

Inference Type

Greedy Decoding (do_sample=False) is used for deterministic and consistent code fixes.

The model initialization is handled in the FastAPI startup hook (main.py -> initialize_llm()), ensuring the potentially slow model loading process does not block the API worker processes during runtime.

3. API Functionality (POST /local_fix)

The endpoint adheres strictly to the required input/output schema.

Input JSON (FixRequest):

{
    "language": "java",
    "cwe": "CWE-89",
    "code": "..."
}


Output JSON (FixResponse):

{
    "fixed_code": "...",
    "diff": "...",
    "explanation": "...",
    "model_used": "Qwen/Qwen2.5-1.5B-Instruct",
    "token_usage": {
        "input_tokens": 125,
        "output_tokens": 350
    },
    "latency_ms": 12345.67
}


4. Prompt Design and Structured Output

A structured instruction-following approach was used to ensure reliable and parsable output:

System Prompt: Defines the model's persona (Expert Security Engineer) and the mandatory XML-like output format (<FIXED_CODE>, <DIFF>, <EXPLANATION>).

User Query: Clearly separates the context (Language, CWE ID) from the code snippet.

Parsing: The parse_model_output function in app/llm_service.py uses Regular Expressions (re.search) to robustly extract content between the defined XML-like tags, minimizing the risk of corrupted JSON output.

5. Logging & Metrics

The system logs all required metrics upon every successful call in app/api_routes.py:

Input Token Count: Calculated via tokenizer.encode() before inference.

Output Token Count: Calculated from the length of the generated IDs (output_ids.shape[0]).

Latency: Time difference (time.time()) is captured from the start of the run_inference function to the completion of model parsing, reported in milliseconds (latency_ms).

Log Destination: Logs are printed to the console using Python's standard logging library, formatted as JSON string for easy parsing/aggregation.

6. Testing

Run the provided testing script to send three distinct vulnerability examples to the service:

python test_local.py


7. Assumptions and Limitations

Hardware Dependency (CPU): The solution is defaulted to CPU inference (device_map="cpu"). Performance (latency) will be very high for a 1.5B model on a standard CPU. For production use, or for larger models (7B+), a CUDA-enabled GPU setup would be mandatory.

Model Availability: This solution assumes the evaluators have network access to download the Qwen/Qwen2.5-1.5B-Instruct weights from Hugging Face.

Diff Tooling: The LLM is instructed to generate the diff. In a real-world scenario, a dedicated code analysis/diff library (like difflib in Python) would be used to calculate a precise, machine-verified diff for reliability.

RAG Implementation: The optional RAG component was not implemented in this base version, focusing first on fulfilling all mandatory requirements with a robust foundation.