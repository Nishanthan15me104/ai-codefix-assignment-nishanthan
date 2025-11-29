# Entersoft AI Code Remediation Microservice (Local Inference)

This repository contains the solution for the Entersoft Security Technical Internship Assignment: AI Code Remediation Microservice.

The solution is built using FastAPI to expose the API endpoint and Hugging Face Transformers for local LLM inference.

## Project Structure

The project is organized into a single Python package (app) and root files necessary for execution:

    ```bash
    ai-codefix-assignment-nishanthan/
    │
    ├── app/
    │   ├── __init__.py
    │   ├── api_routes.py
    │   ├── llm_service.py
    │   ├── models.py
    │   └── rag_service.py
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

| File               | Location | Explanation                                                                                                                                                                                                                                                                                 |
| ------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| main.py            | Root     | The entry point for the FastAPI application. It initializes the FastAPI app, includes the API router, and calls the critical initialize_llm() and initialize_rag() functions on startup.                                                                                                    |
| app/api_routes.py  | app/     | Defines the /local_fix API endpoint using FastAPI's APIRouter. It handles incoming fix requests, calls run_inference from llm_service.py, logs the token usage/latency metrics, and returns the structured FixResponse.                                                                     |
| app/llm_service.py | app/     | Contains the core logic for the Large Language Model (LLM). It handles downloading and loading the GGUF model via llama-cpp-python, engineers the RAG-enhanced prompt, runs the chat completion inference, and includes robust logic to parse the structured XML output from the LLM.       |
| app/rag_service.py | app/     | Implements the Retrieval-Augmented Generation (RAG) system. It uses Sentence-Transformers for embeddings and FAISS for fast vector search. It loads security recipes from the recipes/ directory and contains the retrieve_context function to find relevant guidance for a given CWE/code. |
| app/models.py      | app/     | Defines the Pydantic schemas (FixRequest, TokenUsage, FixResponse) used for data validation and consistency across the API requests and responses.                                                                                                                                          |
| test_local.py      | Root     | A client script for running integration tests. It defines test cases (Python SQLI, JavaScript XSS), sends requests to the /local_fix endpoint, and prints the detailed results, including fixed code, diff, explanation, and performance metrics.                                           |
| docker-compose.yml | Root     | Configuration file for defining and running the multi-container Docker application, including the code-fix-service (FastAPI/LLM) and the test-runner service.                                                                                                                               |
| Dockerfile         | Root     | Instructions for building the Docker image, including installing Python dependencies and the complex compilation requirements for llama-cpp-python.                                                                                                                                         |
## set-up Instruction 

### Docker Setup

#### step 1 clone repo
```bash
git clone https://github.com/Nishanthan15me104/ai-codefix-assignment-nishanthan.git
```
once repo is cloned from the root proceed with next step



#### step 2 build
```bash
docker compose build
```
approximately takes 30 minutes to complete

#### step 3 compose 
```bash
docker compose up
```
- note: takes more time for the first time (due to model download)

#### step 3 to check test runner alone  



## Sample output: 
```bash
 [STATUS] Sending request for Test Case 1: Python SQL Injection (CWE-89) - Should use RAG for parameterized query recipe... Awaiting response (Max 10 minutes timeout).
test-runner-1  |
test-runner-1  | [ INFERENCE METRICS ]
test-runner-1  | {
test-runner-1  |     "model_used": "second-state/StarCoder2-3B-GGUF",
test-runner-1  |     "input_tokens": "N/A",
test-runner-1  |     "output_tokens": "N/A",
test-runner-1  |     "server_latency_ms": "249842.14 ms",
test-runner-1  |     "client_latency_ms": "250253.08 ms"
test-runner-1  | }
test-runner-1  |
test-runner-1  | [ FIXED CODE ]
test-runner-1  | def get_user_data(username, db_cursor):
test-runner-1  |     query = "SELECT * FROM users WHERE username = %s"
test-runner-1  |     db_cursor.execute(query, (username,))
test-runner-1  |     return db_cursor.fetchone()
test-runner-1  |
test-runner-1  | [ DIFF ]
test-runner-1  | --- get_user_data.py   2019-08-30 15:46:47.000000000 -0400
test-runner-1  | +++ get_user_data_fixed.py     2019-08-30 15:46:47.000000000 -0400
test-runner-1  | @@ -1,5 +1,5 @@
test-runner-1  |  def get_user_data(username, db_cursor):
test-runner-1  |      query = "SELECT * FROM users WHERE username = %s"
test-runner-1  | -    db_cursor.execute(query)
test-runner-1  | +    db_cursor.execute(query, (username,))
test-runner-1  |      return db_cursor.fetchone()
test-runner-1  |
test-runner-1  | [ EXPLANATION ]
test-runner-1  | The vulnerable code is a SQL Injection attack. The vulnerability occurs because the user input is directly concatenated into an SQL query string. This allows for SQL injection attacks. To prevent this, we must use parameterized queries (prepared statements). We can do so by replacing user input variables with placeholders in the SQL query string.
```

## Model and Inference Details

| Component | Detail | Observation from Logs |
|----------|--------|------------------------|
| Model Name | starcoder2-3b-Q4_K_M.gguf | The service successfully downloaded and loaded this file. |
| Hugging Face ID | second-state/StarCoder2-3B-GGUF | Source noted in the Remediation Log. |
| Inference Library | llama-cpp-python | Confirmed by the log: "GGUF Model loaded successfully via llama-cpp-python." |
| Inference Hardware | CPU bound | Confirmed by the log: "Loading model from: /app/starcoder2-3b-Q4_K_M.gguf (CPU bound)" |
| Prompt Structure | RAG for recipe | The Test Case 1 description suggests a Retrieval-Augmented Generation (RAG) approach is used to inject a security "recipe" (e.g., parameterized query best practice) into the prompt alongside the vulnerable code. |

---

## 📝 Example Inputs and Outputs

The logs capture the complete cycle for Test Case 1: **Python SQL Injection (CWE-89).**

### Input (Vulnerable Code)

The model received a vulnerable Python function for processing:

```python
def get_user_data(username, db_cursor):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    db_cursor.execute(query)
    return db_cursor.fetchone()
```

### Output (Fixed Code and Explanation)

The service returned a fixed version, though the provided log snippets show an incorrect fix that still uses f-string formatting but changes the quotes, which does not prevent SQL Injection (the final diff shows double quotes, but the LLM reasoning is flawed).


| Field                   | Content                                                                                                                                                                                                |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Fixed Code (LLM Output) | `python def get_user_data(username, db_cursor): query = f"SELECT * FROM users WHERE username = \"{username}\"" db_cursor.execute(query) return db_cursor.fetchone()`                                   |
| Explanation Snippet     | "The SQL injection vulnerability is caused by the use of single quotes... To fix this issue, you can escape the single quote with a backslash (') or wrap the username variable in double quotes (")." |
| Remediation Log         | `{"model": "second-state/StarCoder2-3B-GGUF", "language": "python", "cwe": "CWE-89", "status": "Success"}`                                                                                             |

### Output (Fixed Code and Explanation)

The service returned a fixed version, though the provided log snippets show an incorrect fix that still uses f-string formatting but changes the quotes, which does not prevent SQL Injection (the final diff shows double quotes, but the LLM reasoning is flawed).

#### Field  
**Content**

**Fixed Code (LLM Output)**  
```python
def get_user_data(username, db_cursor): 
    query = f"SELECT * FROM users WHERE username = \"{username}\"" 
    db_cursor.execute(query) 
    return db_cursor.fetchone()
```
### Explanation Snippet
"The SQL injection vulnerability is caused by the use of single quotes... To fix this issue, you can escape the single quote with a backslash (') or wrap the username variable in double quotes (")."

#### Remediation Log

```bash
{"model": "second-state/StarCoder2-3B-GGUF", "language": "python", "cwe": "CWE-89", "status": "Success"}
```



| Component              | Detail                          | Observation from Logs                                                                                                                       |
| ---------------------- | ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| **Model Name**         | starcoder2-3b-Q4_K_M.gguf       | The service successfully downloaded and loaded this file.                                                                                   |
| **Hugging Face ID**    | second-state/StarCoder2-3B-GGUF | Source noted in the Remediation Log.                                                                                                        |
| **Inference Library**  | llama-cpp-python                | Confirmed by the log: "GGUF Model loaded successfully via llama-cpp-python."                                                                |
| **Inference Hardware** | CPU bound                       | Confirmed by the log: "Loading model from: /app/starcoder2-3b-Q4_K_M.gguf (CPU bound)"                                                      |
| **Prompt Structure**   | RAG for recipe                  | The Test Case 1 description suggests a Retrieval-Augmented Generation (RAG) approach is used to inject a security "recipe" into the prompt. |


| Startup Step         | Start Time | End Time | Latency                    |
| -------------------- | ---------- | -------- | -------------------------- |
| Model Download       | 07:50:04   | 07:58:47 | 8 minutes, 43 seconds      |
| Model Load           | 07:58:47   | 07:58:51 | 4 seconds                  |
| **Total Ready Time** | 07:50:04   | 07:58:51 | **~8 minutes, 47 seconds** |

### 2. Inference Latency (Test Case 1)

The time taken for the LLM to process the request is important for production viability.

Latency: 55713.49ms

Time: ~55.7 seconds (Nearly a minute per fix)

Tokens: input_tokens: 286, output_tokens: 242

## Assumptions and Limitations

**Mandatory Runtime Download:**
It is assumed the model must be downloaded fresh during every docker compose up. This dictates the long startup delay.

**CPU Inference Bottleneck:**
Inference is slow (~56 seconds per request) because the model runs fully on CPU.

**Model Quality Issue:**
The fix for CWE-89 was insufficient and insecure, indicating a need for better RAG context, improved model, or better prompt/parsing logic.

**Version Warning:**
Docker Compose shows a warning about the obsolete version attribute in docker-compose.yml, which should be removed.