import json
from embedding_model import EmbeddingModel
from embedding_cache import EmbeddingCache

INPUT_FILES = [
    "data/chunkfile/cve_chunks.jsonl",
    "data/chunkfile/cwe_owasp_chunks.jsonl"
]

OUTPUT_FILES = [
    "data/embedding/embedded_chunks_cve.json",
    "data/embedding/embedded_chunks_cwe_owasp.json"
]


def load_chunks(index: int):
    chunks = []
    with open(INPUT_FILES[index], "r") as f:
        for line in f:
            chunks.append(json.loads(line))
    return chunks


def main():
    model = EmbeddingModel()
    cache = EmbeddingCache()

    for i in range(len(INPUT_FILES)):
        chunks = load_chunks(i)

        texts = []
        valid_chunks = []

        for chunk in chunks:
            text =  "Represent this cybersecurity passage for retrieval: "+ chunk["text"]

            cached = cache.get(text)
            if cached:
                chunk["embedding"] = cached
            else:
                texts.append(text)
                valid_chunks.append(chunk)

        print(f"Encoding {len(valid_chunks)} new chunks...")

        if texts:
            embeddings = model.encode(texts)

            for chunk, emb in zip(valid_chunks, embeddings):
                chunk["embedding"] = emb.tolist()
                cache.set(chunk["text"], emb)

        cache.save()

        with open(OUTPUT_FILES[i], "w") as f:
            json.dump(chunks, f)

        print(f"Saved embeddings to {OUTPUT_FILES[i]}")


if __name__ == "__main__":
    main()