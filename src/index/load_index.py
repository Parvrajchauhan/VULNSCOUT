import pickle
import faiss


def load_faiss_index(index_path):
    print(f"Loading index: {index_path}")
    return faiss.read_index(index_path)


def load_metadata(meta_path):
    print(f"Loading metadata: {meta_path}")
    with open(meta_path, "rb") as f:
        return pickle.load(f)
