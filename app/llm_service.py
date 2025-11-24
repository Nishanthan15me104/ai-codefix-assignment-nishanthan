import time
import re
import logging
import os
from fastapi import HTTPException
# Switched from Hugging Face transformers/torch to llama-cpp-python
from llama_cpp import Llama, llama_chat_format
from huggingface_hub import hf_hub_download

# --- Configuration and Setup ---

logger = logging.getLogger(__name__)

# Model details (Updated to reference the GGUF file)
GGUF_MODEL_REPO = "Qwen/Qwen2.5-1.5B-Instruct-GGUF"
GGUF_MODEL_FILE = "qwen2.5-1.5b-instruct-q4_k_m.gguf" # Q4_K_M is a good balance of speed/quality
MODEL_NAME = GGUF_MODEL_REPO # Use the repo name for the logs

# Global variables to hold model components
llm_model = None
# Tokenizer is now managed internally by llama-cpp-python
# We still need the model path for initialization
MODEL_PATH = os.path.join(os.getcwd(), GGUF_MODEL_FILE)

# --- LLM Initialization ---

def initialize_llm():
    """
    Loads the GGUF model via llama-cpp-python.
    This function now also handles downloading the GGUF file from Hugging Face Hub.
    """
    global llm_model
    
    if llm_model is not None:
        logger.info("LLM already initialized.")
        return
        
    try:
        logger.info(f"Checking for GGUF model file: {GGUF_MODEL_FILE}...")
        
        # 1. Download the GGUF file if it doesn't exist locally
        if not os.path.exists(MODEL_PATH):
            logger.info(f"Downloading {GGUF_MODEL_FILE} from Hugging Face Hub...")
            hf_hub_download(
                repo_id=GGUF_MODEL_REPO,
                filename=GGUF_MODEL_FILE,
                local_dir=".", # Download to the root directory
                local_dir_use_symlinks=False
            )
            logger.info("Download complete.")

        # 2. Load the GGUF model using Llama.cpp (optimized for CPU)
        logger.info(f"Loading model from: {MODEL_PATH} (CPU bound)")
        
        # NOTE: n_ctx controls context size (max tokens). Set to 2048 for a balance.
        # NOTE: n_threads is crucial for CPU performance, set it to 4 or higher if available.
        llm_model = Llama(
            model_path=MODEL_PATH,
            n_ctx=2048,           # Context window size
            n_gpu_layers=0,       # Force CPU only (0 layers)
            verbose=False,        # Suppress Llama.cpp boilerplate logs
            n_threads=4           # Use 4 CPU threads for inference (adjust based on machine)
        )
        
        logger.info("GGUF Model loaded successfully via llama-cpp-python.")
        
    except Exception as e:
        logger.error(f"Failed to load GGUF model: {e}")
        llm_model = None


# --- Utility Function: Prompt Engineering ---

def create_prompt_messages(language: str, cwe: str, code: str) -> list:
    """
    Creates the structured instruction prompt for the Llama model using the chat template.
    The response is guided to use specific XML-like tags for robust parsing.
    """
    
    # --- UPDATED SYSTEM PROMPT: Added structure instruction for reliability ---
    system_prompt = (
        "You are an expert Security Engineer and AI Code Remediation assistant. "
        "Your task is to analyze the provided vulnerable code snippet based on the CWE ID, "
        "generate a secure fixed version, explain the vulnerability and the fix, and provide a clear diff. "
        "You MUST wrap your ENTIRE output in the following XML-like tags, using code blocks where applicable: "
        "<FIXED_CODE>...fixed code...</FIXED_CODE>, "
        "<DIFF>...standard diff...</DIFF>, "
        "<EXPLANATION>...text explanation...</EXPLANATION>. "
        "Do not include any pre-amble, comments, or text outside these three tags. "
        
        "\n\n--- REQUIRED OUTPUT FORMAT EXAMPLE (STRICTLY FOLLOW THIS) ---\n"
        "<FIXED_CODE>\n"
        "```python\n# Fixed Code Here\n```\n"
        "</FIXED_CODE>\n"
        "<DIFF>\n"
        "```diff\n# Diff Here\n```\n"
        "</DIFF>\n"
        "<EXPLANATION>\n"
        "This is the explanation of the fix.\n"
        "</EXPLANATION>\n"
    )
    # --- END UPDATED SYSTEM PROMPT ---

    # User query containing the context and the vulnerable code
    user_query = (
        f"Vulnerability Details:\n"
        f"- Language: {language}\n"
        f"- CWE ID: {cwe}\n"
        f"\n"
        f"Vulnerable Code to Fix:\n"
        f"```\n{code.strip()}\n```"
    )

    # Qwen instruction template format (used by llama_cpp for Qwen models)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_query}
    ]
    
    return messages

# --- Utility Function: Output Parsing (Remains the same) ---

def parse_model_output(output: str) -> dict:
    """Parses the structured output from the LLM based on defined tags."""
    
    # Define regex patterns for extraction
    fixed_code_match = re.search(r"<FIXED_CODE>(.*?)</FIXED_CODE>", output, re.DOTALL)
    diff_match = re.search(r"<DIFF>(.*?)</DIFF>", output, re.DOTALL)
    explanation_match = re.search(r"<EXPLANATION>(.*?)</EXPLANATION>", output, re.DOTALL)

    # Extract and clean content
    parsed_output = {
        # CRITICAL FIX: The LLM tends to put the content inside another code block.
        # We must now strip the external code blocks that the LLM may introduce 
        # based on the new explicit prompt example.
        "fixed_code": fixed_code_match.group(1).strip().strip("