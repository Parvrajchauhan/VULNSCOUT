import re
from src.test.truth import GROUND_TRUTH

def normalize(text):
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s/.$_-]', ' ', text)
    return text


def extract_text(results):
    full_text = ""
    for r in results.get("cve_results", []) + results.get("cwe_results", []):
        data     = r.get("data", {})
        text     = data.get("text", "")
        metadata = str(data.get("metadata", {}))
        full_text += " " + text + " " + metadata
    return normalize(full_text)


#Metric 1: Recall@K 
# What fraction of expected keywords appear anywhere in the retrieved text?
# High recall = nothing important was missed.
def keyword_recall(retrieved_text, expected_keywords):
    hits = sum(1 for kw in expected_keywords if kw in retrieved_text)
    return hits / len(expected_keywords) if expected_keywords else 0.0



#  Metric 2: MRR (Mean Reciprocal Rank) 
# For each expected keyword, find the rank (1-indexed) of the first result
# chunk that contains it, then average the reciprocals.
#
# Why it matters for VulnScout:
#   Your FAISS pipeline returns an ordered list of chunks. MRR tells you
#   whether relevant chunks surface at rank 1–2 (good) or rank 8–10 (bad).
#   A perfect MRR=1.0 means every keyword was found in the very first chunk.
#   This is especially useful for diagnosing the cross-modal augmentation:
#   if MRR drops on `cve_first` queries, the centroid shift is burying hits.
def mean_reciprocal_rank(results, expected_keywords):
    if not results or not expected_keywords:
        return 0.0

    # Pre-normalise each chunk once
    chunk_texts = []
    for r in results:
        data = r.get("data", {})
        text = data.get("text", "") + " " + str(data.get("metadata", {}))
        chunk_texts.append(normalize(text))

    reciprocal_ranks = []
    for kw in expected_keywords:
        norm_kw = normalize(kw)
        rank = next(
            (i + 1 for i, ct in enumerate(chunk_texts) if norm_kw in ct),
            None   # keyword not found in any chunk
        )
        reciprocal_ranks.append(1.0 / rank if rank else 0.0)

    return sum(reciprocal_ranks) / len(reciprocal_ranks)


def score_results(query, results):
    expected  = GROUND_TRUTH.get(query, [])
    full_text = extract_text(results)

    recall    = keyword_recall(full_text, expected)

    all_hits = results.get("cve_results", []) + results.get("cwe_results", [])
    mrr      = mean_reciprocal_rank(all_hits, expected)

    return {
        "query":     query,
        "recall":    round(recall,    3),
        "mrr":       round(mrr,       3),
    }