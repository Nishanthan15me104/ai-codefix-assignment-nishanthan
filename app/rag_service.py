import os
import logging
from typing import List, Optional
from sentence_transformers import SentenceTransformer
import faiss
import numpy as np
from pathlib import Path
from numpy import linalg as LA # For explicit vector normalization

logger = logging.getLogger(__name__)

# --- Configuration ---
RECIPES_DIR = "recipes"
EMBEDDING_MODEL_NAME = 'all-MiniLM-L6-v2' # A fast and high-quality model

# Retrieve the cache path from environment variable (default to standard path if unset)
MODEL_CACHE_DIR = os.environ.get('MODEL_DOWNLOAD_PATH', None) # Will be '/app/models' from compose file

# Global variables
rag_model: Optional[SentenceTransformer] = None
faiss_index: Optional[faiss.IndexFlatL2] = None
recipe_texts: List[str] = []
# Map index to original file content/CWE (e.g., {0: "CWE-79"})
recipe_cwe_map: dict[int, str] = {} 

# --- Initialization ---

def initialize_rag():
    """
    Loads the sentence embedding model and creates the FAISS index.
    """
    global rag_model, faiss_index, recipe_texts, recipe_cwe_map

    if faiss_index is not None:
        logger.info("RAG system already initialized.")
        return

    logger.info("Initializing RAG system (Sentence-Transformers and FAISS)...")
    try:
        # 1. Load Embedding Model
        # CRITICAL FIX: Pass the cache path to the SentenceTransformer model loader
        if MODEL_CACHE_DIR:
             Path(MODEL_CACHE_DIR).mkdir(parents=True, exist_ok=True) # Ensure the directory exists
        
        rag_model = SentenceTransformer(
            EMBEDDING_MODEL_NAME, 
            cache_folder=MODEL_CACHE_DIR # Use the persistent volume location
        )
        
        recipes_path = Path(RECIPES_DIR)

        # 2. Load and Process Recipes
        if not recipes_path.is_dir():
            logger.error(f"Recipes directory '{RECIPES_DIR}' not found. Skipping RAG initialization.")
            return

        recipe_files = list(recipes_path.glob('*.txt'))
        
        for file_path in recipe_files:
            try:
                # Assuming filename is like 'CWE-123_description.txt'
                cwe_tag = file_path.name.split('_')[0].upper() 
            except IndexError:
                cwe_tag = file_path.stem.upper()
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                recipe_texts.append(content)
                recipe_cwe_map[len(recipe_texts) - 1] = cwe_tag

        if not recipe_texts:
            logger.warning(f"No recipe files found in '{RECIPES_DIR}'. RAG will be inactive.")
            return

        # 3. Create Embeddings and Normalize
        logger.info(f"Embedding {len(recipe_texts)} recipe documents...")
        
        # Sentence-Transformers typically normalizes, but we do it explicitly for FAISS/L2 safety
        embeddings = rag_model.encode(recipe_texts, convert_to_tensor=False)
        embeddings = np.array([e for e in embeddings]).astype('float32')

        # Crucial fix for 'TypeError: norm() got an unexpected keyword argument 'out''
        # We calculate the norm and divide the embeddings by it to perform L2 normalization.
        norms = LA.norm(embeddings, axis=1, keepdims=True)
        embeddings = embeddings / norms
        
        dimension = embeddings.shape[1]

        # 4. Create and Populate FAISS Index (using L2 distance)
        faiss_index = faiss.IndexFlatL2(dimension)
        faiss_index.add(embeddings)
        
        logger.info(f"RAG system successfully initialized. FAISS Index size: {faiss_index.ntotal}")
        logger.info("RAG INITIALIZATION COMPLETE.") 

    except Exception as e:
        logger.error(f"Failed to initialize RAG system: {e}", exc_info=True)
        faiss_index = None
        rag_model = None
        logger.error("RAG INITIALIZATION FAILED.")


# --- Retrieval Function ---
def retrieve_context(cwe: str, code: str, k: int = 1) -> Optional[str]:
    """
    Retrieves the most relevant security recipe based on the CWE or code snippet.
    
    CRITICAL FIX: This function now forces an attempt to initialize RAG 
    if it is found inactive when called, resolving the race condition with the test runner.
    """
    # 1. Check if RAG is active, if not, attempt to initialize it synchronously.
    if faiss_index is None or rag_model is None:
        logger.warning("RAG system is inactive on retrieval attempt. Forcing synchronous initialization.")
        initialize_rag() # Call the safe, idempotent initialization function

    # 2. Final check after initialization attempt
    if faiss_index is None or rag_model is None:
        logger.warning("RAG system is still inactive. Cannot retrieve context.")
        return None 

    # The ideal query combines both the explicit CWE and the code context
    query_text = f"CWE ID: {cwe}. Code to fix: {code.strip()}"
    logger.info(f"RAG QUERY: {query_text[:100]}...")
    
    try:
        # Encode the query and convert to float32 numpy array
        query_embedding = rag_model.encode([query_text], convert_to_tensor=False).astype('float32')
        
        # Normalize the query vector for comparison with the normalized index vectors
        # Using the same safe normalization method as initialize_rag
        norms = LA.norm(query_embedding, axis=1, keepdims=True)
        query_embedding = query_embedding / norms

        # Perform FAISS search
        DISTANCE_THRESHOLD = 1.2 
        
        distances, indices = faiss_index.search(query_embedding, k=k)
        
        # Check the top distance
        if indices.size > 0:
            top_distance = distances[0][0]
            logger.info(f"RAG RETRIEVAL: Top-1 Index: {indices[0][0]}, Squared L2 Distance: {top_distance:.4f}")
            
            # Retrieve only if the distance is below the threshold
            if top_distance > DISTANCE_THRESHOLD: 
                logger.info(f"No highly relevant recipe found (Distance {top_distance:.4f} > {DISTANCE_THRESHOLD}, Cos Sim < 0.4).")
                return None

            # Retrieve and assemble the results
            retrieved_contexts = []
            for i in indices[0]:
                if i < len(recipe_texts):
                    context_content = recipe_texts[i]
                    cwe_tag = recipe_cwe_map.get(i, 'UNKNOWN_CWE')
                    
                    # Log a sample (max 150 chars, single line) for debugging
                    sample_content = context_content[:150].replace('\n', ' ')
                    logger.warning(f"RAG CHUNK RETRIEVED (CWE {cwe_tag}): Content Sample: {sample_content}...")
                    
                    retrieved_contexts.append(context_content)
            
            if retrieved_contexts:
                logger.info(f"RAG: Successfully retrieved {len(retrieved_contexts)} context(s) for CWE {cwe}")
                # Format the context for injection into the system prompt
                return "\n\n--- RAG Context (Security Fix Guidance) ---\n\n" + "\n\n".join(retrieved_contexts)
        
        return None

    except Exception as e:
        logger.error(f"RAG retrieval failed: {e}", exc_info=True)
        return None