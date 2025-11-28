import logging
from fastapi import FastAPI
from app.api_routes import router as api_router
# Import the initialization functions from the LLM and RAG services
from app.llm_service import initialize_llm
from app.rag_service import initialize_rag

# --- Configuration and Setup ---

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- FastAPI App Initialization ---

app = FastAPI(title="Entersoft AI Code-Fix Microservice (Modular with RAG)")

# Include the router containing all API endpoints
app.include_router(api_router)


# --- Application Lifecycle Hooks (Crucial for heavy startup tasks) ---

@app.on_event("startup")
def startup_event():
    """
    Called once when the application starts. Initializes the LLM and RAG.
    """
    # Initialize the LLM first
    initialize_llm()
    # Initialize the RAG system
    initialize_rag()

# --- Optional Shutdown Hook ---
@app.on_event("shutdown")
def shutdown_event():
    """Placeholder for future resource cleanup."""
    logging.info("FastAPI application is shutting down.")