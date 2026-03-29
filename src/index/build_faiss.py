import os
import json
import pickle
import numpy as np
import faiss
from tqdm import tqdm

DIM = 1024

CVE_PATH = "data/embedding/embedded_chunks_cve.json"
CWE_PATH = "data/embedding/embedded_chunks_cwe_owasp.json"

OUTPUT_DIR = "data/index"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def load_embeddings(file_path):
    embeddings = []
    metadata = []

    print(f"Loading: {file_path}")

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    for item in tqdm(data):
        emb = item.get("embedding")
        if emb is None:
            continue

        embeddings.append(emb)

        meta = {k: v for k, v in item.items() if k != "embedding"}
        metadata.append(meta)

    embeddings = np.array(embeddings, dtype="float32")

    return embeddings, metadata


def normalize_embeddings(embeddings):
    faiss.normalize_L2(embeddings)
    return embeddings


def build_cve_index(embeddings):
    print("\nBuilding CVE HNSW Index...")


    embeddings = normalize_embeddings(embeddings)

    embeddings_fp16 = embeddings.astype("float16")

    index = faiss.IndexHNSWFlat(DIM, 32)
    index.hnsw.efConstruction = 200
    index.hnsw.efSearch = 64

    index.add(embeddings_fp16.astype("float32"))

    print(f"CVE index size: {index.ntotal}")

    return index

def build_cwe_index(embeddings):
    print("\nBuilding CWE + OWASP Flat Index...")

    embeddings = normalize_embeddings(embeddings)

    embeddings_fp16 = embeddings.astype("float16")

    index = faiss.IndexFlatIP(DIM)

    index.add(embeddings_fp16.astype("float32"))

    print(f"CWE index size: {index.ntotal}")

    return index


def save_index(index, metadata, index_path, meta_path):
    faiss.write_index(index, index_path)

    with open(meta_path, "wb") as f:
        pickle.dump(metadata, f)

    print(f"Saved index → {index_path}")
    print(f"Saved metadata → {meta_path}")


def main():
    cve_embeddings, cve_meta = load_embeddings(CVE_PATH)
    cwe_embeddings, cwe_meta = load_embeddings(CWE_PATH)

    print("\nShapes:")
    print("CVE:", cve_embeddings.shape)
    print("CWE:", cwe_embeddings.shape)

    cve_index = build_cve_index(cve_embeddings)
    cwe_index = build_cwe_index(cwe_embeddings)

    save_index(
        cve_index,
        cve_meta,
        os.path.join(OUTPUT_DIR, "cve_hnsw.index"),
        os.path.join(OUTPUT_DIR, "cve_metadata.pkl"),
    )

    save_index(
        cwe_index,
        cwe_meta,
        os.path.join(OUTPUT_DIR, "cwe_flat.index"),
        os.path.join(OUTPUT_DIR, "cwe_metadata.pkl"),
    )

    print("\nALL DONE")

if __name__ == "__main__":
    main()