Movie Trivia RAG Chatbot

A Retrieval-Augmented Generation (RAG) based chatbot that answers movie-related questions using semantic search, reranking, and LLM-based generation.

This project is designed with a focus on correctness, evaluation, and real-world ambiguity handling rather than demo-only outputs.

Project Overview

The system allows users to ask factual questions about movies such as:

Who directed Inception?
Which Spider-Man movie had Venom?
Who acted in Interstellar?

Instead of relying solely on an LLM’s internal knowledge, the system retrieves relevant context from a movie dataset and generates grounded responses.

Key Features
Semantic search using embeddings
End-to-end RAG pipeline (retrieval → reranking → generation)
Movie-level aggregation to reduce ambiguity
Evaluation metrics (Precision@K, Recall@K)
Controlled context to minimize hallucinations
Modular architecture for future extensions
System Architecture
User Query
   ↓
Query Embedding
   ↓
Vector Retrieval (Top-K)
   ↓
Reranking + Aggregation
   ↓
Context Selection
   ↓
LLM Generation
   ↓
Final Answer
Core Components
1. Data Processing and Chunking

Movie data is split into structured chunks containing:

Movie title
Cast
Director
Plot summary

Chunking improves retrieval precision and reduces irrelevant context.

2. Embeddings
Generated using sentence-transformers
Converts text into dense vector representations
Enables semantic similarity search instead of keyword matching
3. Vector Retrieval
Retrieves top-K relevant chunks using cosine similarity
Optimized for high recall to ensure relevant data is not missed
4. Reranking and Aggregation (Key Design Decision)

Instead of directly passing retrieved chunks to the LLM:

Chunks are grouped by movie title
Relevance scores are aggregated per movie
Movies are ranked based on total score
The most relevant movie context is selected

This approach reduces:

Mixing of multiple movies in one answer
Franchise-level confusion
Hallucinated combinations
5. Answer Generation
LLM generates answers strictly from retrieved context
Reduces hallucination by constraining generation
Produces concise and factual responses
Evaluation Strategy

The system includes explicit evaluation using:

Precision@K
Recall@K
Manual labeling:
Correct
Hallucinated

Example:

Query: Who directed Inception?
Answer: Christopher Nolan
Precision@5: 0.50
Recall@5: 1.00
Label: Correct

Evaluation is used to guide improvements rather than relying on subjective output quality.

Known Limitations

This version intentionally does not solve all edge cases.

1. Generic Movie Titles

Movies with short or common names (e.g., "Her", "Up") may lead to:

Ambiguous retrieval
Reduced precision
2. Franchise Ambiguity

Queries like:

Who played Spider-Man?

may mix multiple versions across different movies.

3. No Explicit Entity Extraction

The system does not yet use:

Named Entity Recognition
Rule-based disambiguation

These are planned for future versions.

Tech Stack
Python
Sentence-Transformers
FAISS (or equivalent vector database)
LLM API (OpenAI or compatible)
FastAPI (for backend, planned)
Next.js (for frontend, planned)
Project Structure
movie-rag-chatbot/
├── data/
│   └── movie_documents/
├── embeddings/
├── retrieval/
├── reranking/
├── evaluation/
├── api/
├── frontend/
└── README.md
Setup Instructions
1. Clone the repository
git clone <your-repo-url>
cd movie-rag-chatbot
2. Create virtual environment
python -m venv venv
source venv/bin/activate      # Linux / Mac
venv\Scripts\activate         # Windows
3. Install dependencies
pip install -r requirements.txt
4. Run the pipeline
python main.py
Design Philosophy
Correctness over complexity
Known limitations over hidden failures
Evaluation-driven development
Minimal abstraction in early versions

This project avoids premature use of:

Agent frameworks
Heavy orchestration tools
Over-engineered pipelines
Roadmap (Version 2)

Planned improvements:

Movie entity extraction for better disambiguation
Improved handling of franchises
LangChain-based orchestration
Optional agent integration
API deployment with FastAPI
Frontend integration with Next.js
CI/CD pipeline
Status

Version: v1
State: Stable and ready for deployment
Next step: API + frontend integration

Author

Parv Raj

If you want, I can next:

Generate a clean architecture diagram image for GitHub
Add badges (build, license, etc.)
Create a proper requirements.txt
Or write a deployment guide (Docker + cloud)