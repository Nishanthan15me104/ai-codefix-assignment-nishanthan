import time
import re
import logging
import os
from fastapi import HTTPException
from llama_cpp import Llama, llama_chat_format
from huggingface_hub import hf_hub_download

# --- Configuration and Setup ---

logger = logging.getLogger(__name__)

# Model details (Updated to use a reliable GGUF repository)
GGUF_MODEL_REPO = "second-state/StarCoder2-3B-GGUF"
GGUF_MODEL_FILE = "starcoder2-3b-Q4_K_M.gguf"
MODEL_NAME = GGUF_MODEL_REPO # Use the repo name for the logs

# Global variables to hold model components
llm_model = None

# Always default to the current working directory (project root).
MODEL_PATH = os.path.join(os.getcwd(), GGUF_MODEL_FILE)
logger.info(f"Using default project root path for model: {MODEL_PATH}")


# --- LLM Initialization ---

def initialize_llm():
    """
    Loads the GGUF model via llama-cpp-python.
    This function now also handles downloading the GGUF file from Hugging Face Hub.
    """
    global llm_model
    global MODEL_PATH 
    
    if llm_model is not None:
        logger.info("LLM already initialized.")
        return
        
    try:
        logger.info(f"Checking for GGUF model file: {GGUF_MODEL_FILE} at {MODEL_PATH}...")
        
        # 1. Download the GGUF file if it doesn't exist at the determined path
        if not os.path.exists(MODEL_PATH):
            
            # The target path for the download is ALWAYS the current working directory
            download_dir = os.getcwd()
            download_path = os.path.join(download_dir, GGUF_MODEL_FILE)
            
            logger.warning(f"Model file not found at {MODEL_PATH}. Downloading to project root ({download_path}).")
            
            # Use the corrected repository ID and filename
            hf_hub_download(
                repo_id=GGUF_MODEL_REPO,
                filename=GGUF_MODEL_FILE,
                local_dir=download_dir, 
                local_dir_use_symlinks=False
            )
            logger.info("Download complete.")
            
            # Update MODEL_PATH to point to the newly downloaded file 
            MODEL_PATH = download_path
            logger.info(f"Updated active model path to successfully downloaded file: {MODEL_PATH}")


        # 2. Load the GGUF model using Llama.cpp (optimized for CPU)
        logger.info(f"Loading model from: {MODEL_PATH} (CPU bound)")
        
        llm_model = Llama(
            model_path=MODEL_PATH,
            n_ctx=4096,          # Context window kept high
            n_gpu_layers=0,      # Force CPU only (0 layers)
            verbose=False,       # Suppress Llama.cpp boilerplate logs
            n_threads=6          # Threads kept high for performance
        )
        
        logger.info("GGUF Model loaded successfully via llama-cpp-python.")
        
    except Exception as e:
        logger.error(f"Failed to load GGUF model: {e}")
        llm_model = None


# --- Utility Function: Prompt Engineering ---

def create_prompt_messages(language: str, cwe: str, code: str) -> list:
    """
    Creates the structured instruction prompt for the LLM using the chat template.
    """
    
    # Content-specific instruction based on observed failures:
    content_instruction = ""
    if cwe == "CWE-89" and language.lower() in ["python", "java"]:
        content_instruction = (
            "Crucially, for SQL Injection, you MUST use parameterized queries (placeholders, like %s or ?). "
            "Do NOT use string concatenation or interpolation (f-strings). "
            "The fixed code MUST call `db_cursor.execute` with the query string and a separate tuple of parameters."
        )
    elif cwe == "CWE-79" and language.lower() in ["javascript", "html"]:
        content_instruction = "Crucially, for XSS, you MUST use properties like `.textContent` instead of `.innerHTML` to safely render user input as plain text."
    elif cwe == "CWE-798" and language.lower() == "java":
        content_instruction = "Crucially, for Hardcoded Credentials, you MUST remove the hardcoded secrets and replace them with a function call to retrieve secrets from a secure external source (e.g., environment variables or a configuration file). Do NOT simply add try-catch blocks."
    
    # Universal Structure Instruction:
    system_prompt = (
        "You are an expert Security Engineer and AI Code Remediation assistant. "
        "Your task is to analyze the provided vulnerable code snippet based on the CWE ID, "
        "generate a secure fixed version, explain the vulnerability and the fix, and provide a clear diff. "
        
        f"{content_instruction} " 
        
        "YOUR ENTIRE RESPONSE MUST STRICTLY USE ONLY THESE THREE XML TAGS, AND NOTHING ELSE. "
        "DO NOT include any introductory sentences, Markdown headings, bold text, or internal model response tokens like [/SYS] or similar template elements. "
        "The three tags are: <FIXED_CODE>...fixed code...</FIXED_CODE>, <DIFF>...standard diff...</DIFF>, and <EXPLANATION>...text explanation...</EXPLANATION>. "
        "The DIFF should contain lines showing old code and new code changes, prefixed with '-' and '+'. "
        "YOUR RESPONSE MUST BEGIN WITH THE <FIXED_CODE> TAG."
    )
    
    # User query containing the context and the vulnerable code
    user_query = (
        f"Vulnerability Details:\n"
        f"- Language: {language}\n"
        f"- CWE ID: {cwe}\n"
        f"\n"
        f"Vulnerable Code to Fix:\n"
        f"```\n{code.strip()}\n```"
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_query}
    ]
    
    return messages

# --- Utility Function: Output Parsing ---

def parse_model_output(output: str) -> dict:
    """
    Parses the structured output from the LLM based on defined tags, 
    with robust fallback mechanisms for missing closing tags or Markdown headers.
    """
    
    flags = re.DOTALL | re.IGNORECASE
    fixed_code = "Parsing Error: Fixed code not found."
    diff = "Parsing Error: Diff not found."
    explanation = "Parsing Error: Explanation not found."

    # Helper function to strip markdown code fences and language specifiers aggressively
    def clean_code_block(content: str) -> str:
        if not content:
            return ""
        
        content = content.strip()
        
        # Remove leading ``` with optional language
        content = re.sub(r"^\s*```[a-zA-Z]*\s*\n?", "", content, 1, re.MULTILINE) 
        
        # Remove trailing ```
        content = re.sub(r"\n?\s*```\s*$", "", content, 1, re.MULTILINE) 
        
        # Remove common internal template noise at the start/end
        content = re.sub(r"^\[FIXED_CODE\]|\[/SYS\]\s*:?", "", content, flags=re.IGNORECASE).strip()
        content = re.sub(r"\[FIXED_CODE\]$", "", content, flags=re.IGNORECASE).strip()

        return content.strip()

    # --- 1. FIXED CODE EXTRACTION (Most Critical) ---
    
    # FIX: PRIORITY 1: Look for a clean Markdown code block first, as the model often puts the actual code there.
    code_block_match = re.search(r"```[a-zA-Z]*\s*\n(.*?)\n\s*```", output, flags)
    if code_block_match:
        fixed_code = code_block_match.group(1).strip()
    
    # PRIORITY 2: Strict XML extraction (Fallback/Confirm)
    fixed_code_xml_match = re.search(r"<FIXED_CODE>\s*(.*?)\s*</FIXED_CODE>", output, flags)
    if fixed_code_xml_match:
        # If both markdown and XML are found, use the cleaner XML content, but always clean it
        if fixed_code.startswith("Parsing Error") or len(fixed_code) < 5:
            fixed_code = clean_code_block(fixed_code_xml_match.group(1))

    # FALLBACK 1.1: Missing closing tag. Capture from <FIXED_CODE> up to the next tag/header.
    if fixed_code.startswith("Parsing Error") or len(fixed_code) < 5:
        fallback_fixed_code_match = re.search(
            r"<FIXED_CODE>\s*(.*?)(?=\s*<DIFF>|\s*<EXPLANATION>|\s*Explanation:|\s*Diff:|\s*The diff is:|\s*Explanation of Vulnerability and the Fix:|$)", 
            output, flags
        )
        if fallback_fixed_code_match:
            fixed_code = clean_code_block(fallback_fixed_code_match.group(1))

    # --- 2. DIFF EXTRACTION ---
    
    # PRIMARY: Strict XML extraction
    diff_match = re.search(r"<DIFF>\s*(.*?)\s*</DIFF>", output, flags)
    if diff_match:
        diff = clean_code_block(diff_match.group(1))
    
    # FIX: FALLBACK: Aggressive header matching for Diff
    if diff.startswith("Parsing Error") or len(diff) < 5:
        # Updated regex to match the model's specific header text: "The diff between the original and fixed code is as follows:"
        diff_fallback_match = re.search(
            r"(?:Diff:|The diff is:|The diff between the original and fixed code is as follows:)\s*\n?(.*?)(?=<EXPLANATION>|\s*<DIFF>|\s*Explanation:|The explanation of the fix is as follows:|\s*Vulnerability|\s*$)", 
            output, flags
        )
        if diff_fallback_match:
            diff_content = diff_fallback_match.group(1)
            # Clean the diff content by removing the model's incorrect and misplaced tags/headers.
            diff_content = re.sub(r"<\/?FIXED_CODE>|New code :|Old Code:", "", diff_content, flags=flags)
            diff = clean_code_block(diff_content)

    # --- 3. EXPLANATION EXTRACTION ---
    
    # PRIMARY: Strict XML extraction
    explanation_match = re.search(r"<EXPLANATION>\s*(.*?)\s*</EXPLANATION>", output, flags)
    if explanation_match:
        explanation = explanation_match.group(1).strip()
    
    # FIX: FALLBACK 3.1: Aggressive header matching for Explanation
    if explanation.startswith("Parsing Error") or len(explanation) < 5:
        explanation_fallback_match = re.search(
            r"(?:Explanation:|Explanation of Vulnerability and the Fix:|The explanation of the fix is as follows:)\s*\n?(.*?)(?=<DIFF>|\s*<EXPLANATION>|\s*Diff:|\s*The diff is:|\s*Vulnerability|\s*$)", 
            output, flags
        )
        if explanation_fallback_match:
            explanation = explanation_fallback_match.group(1).strip()
            # Clean potential leading code block markers if the model nested it oddly
            explanation = clean_code_block(explanation)
            
    # FIX: FALLBACK 3.2: Capture general introductory text if all else failed.
    if explanation.startswith("Parsing Error") and output.strip():
        intro_text_match = re.search(
            r"^\s*(.*?)\s*(?:```|<FIXED_CODE>|<DIFF>|<EXPLANATION>)",
            output.strip(), flags
        )
        if intro_text_match:
            candidate_explanation = intro_text_match.group(1).strip()
            
            # Only use it if it's substantial (more than 5 words)
            if len(candidate_explanation.split()) > 5:
                 explanation = candidate_explanation.strip()
            else:
                 explanation = "Parsing Error: Explanation not found."


    # --- FINAL CHECK AND ERROR REPORTING ---
    # Filter out empty or placeholder diffs from the model's bad generation
    if diff and (diff.strip() == "..." or "Parsing Error" in diff):
        diff = "Parsing Error: Diff content was empty or non-standard."


    # Final result assembly
    parsed_output = {
        "fixed_code": fixed_code,
        "diff": diff,
        "explanation": explanation,
    }
    
    return parsed_output

# --- Core Inference Function ---

def run_inference(language: str, cwe: str, code: str) -> tuple[dict, int, int, float]:
    """
    Generates the fix using the loaded GGUF model via llama-cpp-python.

    Returns:
        tuple[dict, int, int, float]: (parsed_result, input_tokens, output_tokens, latency_ms)
    """
    
    if llm_model is None:
        logger.error("Attempted inference before model was successfully loaded.")
        raise HTTPException(status_code=503, detail="LLM not loaded. Check model initialization logs.")

    start_time = time.time()
    
    # 1. Create the prompt messages
    messages = create_prompt_messages(language, cwe, code)
    
    # 2. Model Inference using chat completion endpoint
    try:
        # Llama-cpp-python's chat completion automatically handles the Qwen template
        response = llm_model.create_chat_completion(
            messages=messages,
            # Keeping max_tokens high (2048) to ensure full XML structure completion
            max_tokens=2048, 
            temperature=0.0, # Greedy decoding for deterministic code fixes
            # FIX: Added aggressive stop sequences to prevent the model from entering its template loop
            stop=["\n>>", "\n<|endoftext|>", "[/SYS]"], 
        )

        # Extract the generated text
        generated_text = response['choices'][0]['message']['content']
        
        # --- DEBUGGING STEP ---
        logger.info("\n--- RAW LLM OUTPUT START (For Debugging Parser) ---")
        logger.info(generated_text) # <--- THIS LINE PRINTS THE UNMODIFIED LLM RESPONSE
        logger.info("--- RAW LLM OUTPUT END ---\n")
        # ----------------------
        
        # Extract token usage from the response metadata
        token_usage = response['usage']
        input_tokens = token_usage['prompt_tokens']
        output_tokens = token_usage['completion_tokens']

    except Exception as e:
        logger.error(f"Inference failed with llama-cpp: {e}")
        raise HTTPException(status_code=500, detail=f"LLM inference error: {e}")

    # 3. Latency
    end_time = time.time()
    latency_ms = (end_time - start_time) * 1000

    # 4. Parse the structured response
    parsed_result = parse_model_output(generated_text)
    
    return parsed_result, input_tokens, output_tokens, latency_ms