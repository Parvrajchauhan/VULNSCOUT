# embedding/embedding_model.py

from sentence_transformers import SentenceTransformer
import torch


MODEL_NAME = "BAAI/bge-large-en-v1.5"


class EmbeddingModel:
    def __init__(self):
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        print(f" Using device: {self.device}")

        self.model = SentenceTransformer(MODEL_NAME, device=self.device)

        if self.device == "cuda":
            self.model = self.model.half()

    def encode(self, texts):
        return self.model.encode(
            texts,
            batch_size=112,               
            normalize_embeddings=True,
            convert_to_numpy=True,
            show_progress_bar=True
        )