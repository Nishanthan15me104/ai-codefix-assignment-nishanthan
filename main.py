import logging
from fastapi import FastAPI
from app.api_routes import router as api_router
# Import the initialization function from the LLM service
from app.llm_service import initialize_llm

# --- Configuration and Setup ---

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- FastAPI App Initialization ---

# The application is initialized here.
app = FastAPI(title="Entersoft AI Code-Fix Microservice (Modular)")

# Include the router containing all API endpoints
app.include_router(api_router)


# --- Application Lifecycle Hooks (Crucial for heavy startup tasks) ---

@app.on_event("startup")
def startup_event():
    """
    Called once when the application starts. 
    This runs *after* the Uvicorn worker process has fully spawned 
    and defined the 'app' object, preventing the 'Attribute "app" not found' error.
    This is where we initialize the LLM model.
    """
    initialize_llm()

# --- Optional Shutdown Hook ---
@app.on_event("shutdown")
def shutdown_event():
    """Placeholder for future resource cleanup."""
    logging.info("FastAPI application is shutting down.")


# Run instructions for the user:
# 1. Create the 'app' directory and save the three 'app/*.py' files inside it.
# 2. Save this file as main.py in the root directory.
# 3. Ensure dependencies are installed: pip install -r requirements.txt
# 4. Start the service (using the main module): uvicorn main:app --reload