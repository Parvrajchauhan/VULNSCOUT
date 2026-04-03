import os
import numpy as np
import faiss
from concurrent.futures import ThreadPoolExecutor
from src.embedding.embedding_model import EmbeddingModel
from src.index.load_index import load_faiss_index, load_metadata


class HybridRetrievalSystem:
    def __init__(self, index_dir="data/index"):
        self.cve_index_path = os.path.join(index_dir, "cve_hnsw.index")
        self.cve_meta_path  = os.path.join(index_dir, "cve_metadata.pkl")

        self.cwe_index_path = os.path.join(index_dir, "cwe_flat.index")
        self.cwe_meta_path  = os.path.join(index_dir, "cwe_metadata.pkl")

        self.cve_index = load_faiss_index(self.cve_index_path)
        self.cwe_index = load_faiss_index(self.cwe_index_path)

        self.cve_meta = load_metadata(self.cve_meta_path)
        self.cwe_meta = load_metadata(self.cwe_meta_path)

        self.embedder = EmbeddingModel()

        self.CVE_SIGNALS = [
            "cve-", "vulnerability in", "affected version",
            "patch", "cvss", "exploit", "vendor", "product version"
        ]

        self.CWE_SIGNALS = [
            "cwe-", "weakness", "mitigation", "how to prevent",
            "attack pattern", "owasp", "injection", "xss",
            "buffer overflow", "what is", "explain", "why does"
        ]

        print("\nHybrid Retrieval System Ready")
        print(f"CVE vectors: {self.cve_index.ntotal}")
        print(f"CWE vectors: {self.cwe_index.ntotal}")

    def normalize(self, vec: np.ndarray) -> np.ndarray:
        faiss.normalize_L2(vec)
        return vec

    def route_query(self, query: str) -> str:
        q = query.lower()

        cve_score = sum(1 for s in self.CVE_SIGNALS if s in q)
        cwe_score = sum(1 for s in self.CWE_SIGNALS if s in q)

        if cve_score > cwe_score:
            return "cve_first"
        elif cwe_score > cve_score:
            return "cwe_first"
        else:
            return "both"

    def _search_cve(self, query_embedding, k):
        D, I = self.cve_index.search(query_embedding, k)

        return [
            {
                "score": float(d),
                "source": "CVE",
                "data": self.cve_meta[i]
            }
            for d, i in zip(D[0], I[0]) if i != -1
        ]

    def _search_cwe(self, query_embedding, k):
        D, I = self.cwe_index.search(query_embedding, k)

        return [
            {
                "score": float(d),
                "source": "CWE",
                "data": self.cwe_meta[i]
            }
            for d, i in zip(D[0], I[0]) if i != -1
        ]

    def hybrid_search(
        self,
        query_embedding,
        k_primary: int = 10, 
        k_secondary: int = 5,
        route="both"
    ):
        query_embedding = self.normalize(query_embedding.astype("float32"))

        if route == "cve_first":
            results_cve = self._search_cve(query_embedding, k_primary)
            results_cwe= self._search_cwe(query_embedding, k_secondary)

        elif route == "cwe_first":
            results_cwe = self._search_cwe(query_embedding, k_primary)
            results_cve = self._search_cve(query_embedding, k_secondary)

        else:
            with ThreadPoolExecutor(max_workers=2) as executor:
                k = (k_primary + k_secondary) // 2
                results_cve = executor.submit(self._search_cve, query_embedding, k).result()
                results_cwe = executor.submit(self._search_cwe, query_embedding, k).result()

        results_cwe= sorted(results_cwe, key=lambda x: x["score"], reverse=True)
        results_cve= sorted(results_cve, key=lambda x: x["score"], reverse=True)
        CVE_SCORE_FLOOR  = 0.3
        CWE_SCORE_FLOOR  = 0.65

        def filter_by_floor(results, floor):
            filtered = [r for r in results if r["score"] >= floor]
            return filtered

        results_cve = filter_by_floor(results_cve, CVE_SCORE_FLOOR)
        results_cwe = filter_by_floor(results_cwe, CWE_SCORE_FLOOR)
        
        return {
            "cve_results": results_cve,
            "cwe_results": results_cwe,
        }
        
    def query(self, text: str, k_primary: int = 10, k_secondary: int = 5) -> dict:
        route = self.route_query(text)

        prefixed = f"Represent this cybersecurity question for retrieving relevant passages:  {text}"

        embedding = self.embedder.encode([prefixed]) 

        results = self.hybrid_search(
            embedding,
            k_primary=10, 
            k_secondary= 5,
            route=route
        )

        return {
            "query": text,
            "route": route,
            "results": results
        }