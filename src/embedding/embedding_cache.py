import json
import os

CACHE_PATH = "data/embedding/cache.json"

class EmbeddingCache:
    def __init__(self):
        if os.path.exists(CACHE_PATH):
            with open(CACHE_PATH, "r") as f:
                self.cache = json.load(f)
        else:
            self.cache = {}

    def get(self, text):
        return self.cache.get(text)

    def set(self, text, embedding):
        self.cache[text] = embedding.tolist()

    def save(self):
        with open(CACHE_PATH, "w") as f:
            json.dump(self.cache, f)