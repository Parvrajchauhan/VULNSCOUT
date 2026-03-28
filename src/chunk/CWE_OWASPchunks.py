import json
import os
import re

CWE_PATH = "data/raw/CWE/cwe_chunks.json"
OWASP_PATH = "data/raw/OWASP/Top10_json/owasp_top10_2025.json"

OUTPUT_PATH = "data/chunkfile/cwe_owasp_chunks.jsonl"


def load_json(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

def merge_and_add_ids(cwe_data, owasp_data):
    combined = cwe_data + owasp_data

    for idx, item in enumerate(combined):
        item["chunk_id"] = f"chunk_{idx+1}"

    return combined


def save_jsonl(data, output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        for item in data:
            f.write(json.dumps(item) + "\n")



def transform_chunk(chunk):

    def clean_text(text):
        text = text.replace("|", " ")
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    text = clean_text(chunk["text"])
    if len(text) > 1800:
        text = text[:1800]
    meta = chunk["metadata"]

    if "cwe_id" in meta:
        new_meta = {
            "id": meta["cwe_id"],
            "title": meta["cwe_name"],
            "source": "CWE",
            "section": meta["section"],
            "section_type": (
                "mitigation" if "mitigation" in meta["section"]
                else "example" if "attack" in meta["section"]
                else "definition"
            )
        }

    elif "owasp_id" in meta:
        new_meta = {
            "id": f"OWASP-{meta['owasp_id']}",
            "title": meta["category_name"],
            "source": "OWASP",
            "section": meta["section"],
            "section_type": (
                "mitigation" if "prevent" in meta["section"].lower()
                else "example" if "scenario" in meta["section"].lower()
                else "definition"
            )
        }

    return {
        "text": "Represent this cybersecurity passage for retrieval: " + text,
        "metadata": new_meta
    }

def process(data):
    processed = []

    for item in data:
        processed.append(transform_chunk(item))

    return processed

def main():
    print("Loading CWE...")
    cwe_raw = load_json(CWE_PATH)

    print("Loading OWASP...")
    owasp_raw = load_json(OWASP_PATH)

    print("Processing CWE...")
    cwe_processed = process(cwe_raw)

    print("Processing OWASP...")
    owasp_processed = process(owasp_raw)

    print("Merging datasets...")
    final_data = merge_and_add_ids(cwe_processed, owasp_processed)

    print(f"Total merged chunks: {len(final_data)}")

    print("Saving to JSONL...")
    save_jsonl(final_data, OUTPUT_PATH)


if __name__ == "__main__":
    main()