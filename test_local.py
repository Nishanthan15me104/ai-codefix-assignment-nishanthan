import requests
import json
import time
import logging

# Configure logging to see the script's output clearly
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Configuration ---
API_URL = "http://127.0.0.1:8000/local_fix"

# --- Test Cases (Same as before) ---
TEST_CASES = [
    {
        "name": "Test Case 1: Python SQL Injection (CWE-89)",
        "language": "python",
        "cwe": "CWE-89",
        "code": """
def get_user_data(username, db_cursor):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    db_cursor.execute(query)
    return db_cursor.fetchone()
"""
    },
    {
        "name": "Test Case 2: JavaScript XSS (CWE-79)",
        "language": "javascript",
        "cwe": "CWE-79",
        "code": """
function displayComment(comment) {
    document.getElementById('output').innerHTML = comment;
}
"""
    },
    {
        "name": "Test Case 3: Java Hardcoded Credentials (CWE-798)",
        "language": "java",
        "cwe": "CWE-798",
        "code": """
public class DatabaseConnection {
    private static final String DB_USER = "admin";
    private static final String DB_PASS = "Pa$$w0rd123";

    public Connection connect() {
        // ... connection logic using fixed credentials
    }
}
"""
    },
]
# --- Helper Function ---

def run_test(case: dict):
    """Sends a single synchronous request to the API and prints the response."""
    
    logger.info(f"\n--- Running {case['name']} ---")
    
    # IMMEDIATE FEEDBACK: This will print right away, confirming the script is running.
    print(f"[STATUS] Sending request for {case['name']}... Awaiting response (Max 10 minutes timeout).")
    
    # --- Synchronous Request Logic ---
    start_time = time.time()
    response = None
    try:
        # **UPDATED TIMEOUT: Reduced to 600.0 seconds (10 minutes)** # Anticipating much faster performance with GGUF.
        response = requests.post(API_URL, json=case, timeout=600.0) 
        
        # This line will immediately raise an error if the connection fails or if the server returns 4xx/5xx
        response.raise_for_status() 

        end_time = time.time()
        
        # Parse and display results
        data = response.json()
        total_latency = (end_time - start_time) * 1000

        logger.info("API Call Successful.")
        logger.info(f"Total Client-Side Latency: {total_latency:.2f} ms")
        
        # Display core results clearly
        print(json.dumps({
            "model_used": data.get("model_used"),
            "input_tokens": data.get("token_usage", {}).get("input_tokens"),
            "output_tokens": data.get("token_usage", {}).get("output_tokens"),
            "server_latency_ms": f"{data.get('latency_ms'):.2f} ms",
        }, indent=4))

        print("\n[ FIXED CODE ]")
        print(data.get("fixed_code"))

        print("\n[ DIFF ]")
        print(data.get("diff"))
        
        print("\n[ EXPLANATION ]")
        print(data.get("explanation"))
        
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Connection Error: Is the Uvicorn server running? Details: {e}")
    except requests.exceptions.RequestException as e:
        # Catches HTTPStatusError and TimeoutError
        logger.error(f"Request failed for {case['name']}: {e}")
        if response is not None and response.status_code == 503:
            logger.error("Error 503 (Service Unavailable): LLM might not be fully initialized on the server.")
        
    print("\n" + "="*80) # Separator for test cases


# --- Main Execution ---

if __name__ == "__main__":
    print("Starting AI Code Remediation Microservice Test Script (Synchronous Mode)...")
    print(f"Target API: {API_URL}")
    print("NOTE: The first few inferences should now be significantly faster due to GGUF quantization.")
    
    for test_case in TEST_CASES:
        run_test(test_case)

    print("\n" + "="*80)
    print("Testing script finished.")