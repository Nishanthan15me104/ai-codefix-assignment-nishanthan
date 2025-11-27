# app/rag_service.py

import os
import logging
from typing import List, Optional
from sentence_transformers import SentenceTransformer
import faiss
import numpy as np

logger = logging.getLogger(__name__)

# --- Configuration ---
RECIPES_DIR = "recipes"
EMBEDDING_MODEL_NAME = 'all-MiniLM-L6-v2' # A fast and high-quality model

# Global variables
rag_model = None
faiss_index = None
recipe_texts = []
recipe_cwe_map = {} # To map index to original file content/CWE

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
        # This will download the model if not cached
        rag_model = SentenceTransformer(EMBEDDING_MODEL_NAME)
        
        # 2. Load and Process Recipes
        if not os.path.isdir(RECIPES_DIR):
            logger.error(f"Recipes directory '{RECIPES_DIR}' not found. Skipping RAG initialization.")
            return

        recipe_files = [f for f in os.listdir(RECIPES_DIR) if f.endswith('.txt')]
        
        for file_name in recipe_files:
            file_path = os.path.join(RECIPES_DIR, file_name)
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                recipe_texts.append(content)
                recipe_cwe_map[len(recipe_texts) - 1] = file_name.split('_')[0].upper() 

        if not recipe_texts:
            logger.warning(f"No recipe files found in '{RECIPES_DIR}'. RAG will be inactive.")
            return

        # 3. Create Embeddings
        logger.info(f"Embedding {len(recipe_texts)} recipe documents...")
        embeddings = rag_model.encode(recipe_texts, convert_to_tensor=False)
        embeddings = np.array([e for e in embeddings]).astype('float32')
        dimension = embeddings.shape[1]

        # 4. Create and Populate FAISS Index
        faiss_index = faiss.IndexFlatL2(dimension)
        faiss_index.add(embeddings)
        
        logger.info(f"RAG system successfully initialized. FAISS Index size: {faiss_index.ntotal}")

    except Exception as e:
        logger.error(f"Failed to initialize RAG system: {e}")
        faiss_index = None
        rag_model = None


# --- Retrieval Function ---

def retrieve_context(cwe: str, code: str, k: int = 1) -> Optional[str]:
    """
    Retrieves the most relevant security recipe based on the CWE or code snippet.
    """
    if faiss_index is None or rag_model is None:
        return None # RAG system is inactive

    # The ideal query combines both the explicit CWE and the code context
    query_text = f"CWE ID: {cwe}. Code to fix: {code.strip()}"
    
    try:
        # Encode the query
        query_embedding = rag_model.encode([query_text], convert_to_tensor=False).astype('float32')

        # Perform FAISS search
        distances, indices = faiss_index.search(query_embedding, k=k)
        
        # Use a distance threshold to avoid injecting irrelevant context (e.g., 0.6 is a starting point)
        if indices.size == 0 or distances[0][0] > 0.6: 
            logger.info("No highly relevant recipe found in FAISS index.")
            return None

        # Retrieve and assemble the results
        retrieved_contexts = []
        for i in indices[0]:
             if i < len(recipe_texts):
                retrieved_contexts.append(recipe_texts[i])
        
        if retrieved_contexts:
            logger.info(f"RAG: Retrieved top {len(retrieved_contexts)} context(s) for CWE {cwe}")
            # Format the context for injection into the system prompt
            return "\n\n--- RAG Context (Security Fix Guidance) ---\n\n" + "\n\n".join(retrieved_contexts)
        
        return None

    except Exception as e:
        logger.error(f"RAG retrieval failed: {e}")
        return None