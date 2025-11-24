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

# Model details (UPGRADE TO MISTRAL-7B-INSTRUCT-V0.2 FOR BETTER QUALITY/INSTRUCTION FOLLOWING)
GGUF_MODEL_REPO = "TheBloke/Mistral-7B-Instruct-v0.2-GGUF"
GGUF_MODEL_FILE = "mistral-7b-instruct-v0.2.Q4_K_M.gguf" 
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
        # Set n_ctx higher to accommodate the larger model and context.
        llm_model = Llama(
            model_path=MODEL_PATH,
            n_ctx=4096,           # Increased context window for the 7B model
            n_gpu_layers=0,       # Force CPU only (0 layers)
            verbose=False,        # Suppress Llama.cpp boilerplate logs
            n_threads=6           # Increased threads for the larger model (adjust based on machine)
        )
        
        logger.info("GGUF Model loaded successfully via llama-cpp-python.")
        
    except Exception as e:
        logger.error(f"Failed to load GGUF model: {e}")
        llm_model = None


# --- Utility Function: Prompt Engineering ---

def create_prompt_messages(language: str, cwe: str, code: str) -> list:
    """
    Creates the structured instruction prompt for the LLM using the chat template.
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

    # The Mistral/Llama chat template uses simple user/system roles
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_query}
    ]
    
    return messages

# --- Utility Function: Output Parsing ---

def parse_model_output(output: str) -> dict:
    """Parses the structured output from the LLM based on defined tags."""
    
    # Define regex patterns for extraction
    fixed_code_match = re.search(r"<FIXED_CODE>(.*?)</FIXED_CODE>", output, re.DOTALL)
    diff_match = re.search(r"<DIFF>(.*?)</DIFF>", output, re.DOTALL)
    explanation_match = re.search(r"<EXPLANATION>(.*?)</EXPLANATION>", output, re.DOTALL)

    # Helper function to strip markdown code fences and language specifiers aggressively
    def clean_code_block(content: str) -> str:
        if not content:
            return ""
        
        # 1. Strip leading/trailing whitespace
        content = content.strip()
        
        # 2. Use regex to remove leading/trailing markdown fences (```) 
        #    and optional language specifiers (python, diff, etc.)
        # Remove leading ``` with optional language
        content = re.sub(r"^\s*```[a-zA-Z]*\s*\n?", "", content, 1, re.MULTILINE) 
        
        # Remove trailing ```
        content = re.sub(r"\n?\s*```\s*$", "", content, 1, re.MULTILINE) 
        
        return content.strip()

    # Extract and clean content
    parsed_output = {
        # Apply the aggressive cleaning function for code and diff
        "fixed_code": clean_code_block(fixed_code_match.group(1)) if fixed_code_match else "Parsing Error: Fixed code not found.",
        "diff": clean_code_block(diff_match.group(1)) if diff_match else "Parsing Error: Diff not found.",
        "explanation": explanation_match.group(1).strip() if explanation_match else "Parsing Error: Explanation not found.",
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
        # Llama-cpp-python's chat completion automatically handles the Mistral template
        response = llm_model.create_chat_completion(
            messages=messages,
            max_tokens=768, # Increased max_tokens for the larger model and more detailed output
            temperature=0.0, # Greedy decoding for deterministic code fixes
            # Mistral models don't typically need an explicit stop sequence like Qwen, 
            # but we can leave the default end-of-text marker.
        )

        # Extract the generated text
        generated_text = response['choices'][0]['message']['content']
        
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