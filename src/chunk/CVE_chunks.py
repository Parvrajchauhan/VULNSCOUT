import json
import os
from collections import defaultdict
from datetime import datetime

MAX_CHARS = 1800

CVE_FILES = [
    "data/raw/NVD_CVE/cve_processed1.jsonl",
    "data/raw/NVD_CVE/cve_processed2.jsonl"
]

OUTPUT_PATH = "data/chunkfile/cve_chunks.jsonl"


def load_jsonl(file_path):
    data = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            data.append(json.loads(line))
    return data


def get_year(date_str):
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").year
    except:
        return "unknown"


def group_cves(data):
    grouped = defaultdict(list)

    for item in data:
        meta = item.get("metadata", {})
        year = get_year(meta.get("published_date", ""))
        severity = meta.get("cvss_severity", "UNKNOWN")

        key = (year, severity)
        grouped[key].append(item)

    return grouped


def split_oversized(chunk):
    if len(chunk["text"]) <= MAX_CHARS:
        chunk["text_length"] = len(chunk["text"])
        return [chunk]

    sentences = [s.strip() for s in chunk["text"].split(". ") if s.strip()]

    parts = []
    current_sentences = []

    for sentence in sentences:
        sentence = sentence + ". "
        current_text = " ".join(current_sentences)

        if len(current_text) + len(sentence) > MAX_CHARS and current_sentences:
            parts.append(current_sentences.copy())

            current_sentences = [current_sentences[-1], sentence.strip()]
        else:
            current_sentences.append(sentence.strip())

    if current_sentences:
        parts.append(current_sentences)

    split_chunks = []
    for i, sent_list in enumerate(parts):
        text = ". ".join(sent_list).strip()
        if not text.endswith("."):
            text += "."

        split_chunks.append({
            **chunk,
            "chunk_id": f"{chunk['chunk_id']}-pt{i+1}",
            "text": text,
            "text_length": len(text)
        })

    return split_chunks


def hard_cap_split(chunk):
    text = chunk["text"]

    parts = []
    for i in range(0, len(text), MAX_CHARS):
        part = text[i:i+MAX_CHARS]

        parts.append({
            **chunk,
            "chunk_id": f"{chunk['chunk_id']}-hc{len(parts)+1}",
            "text": part,
            "text_length": len(part)
        })

    return parts


def create_chunks(grouped_data):
    final_chunks = []
    chunk_id = 1

    for (year, severity), items in grouped_data.items():

        items = sorted(items, key=lambda x: x["metadata"].get("cve_id", ""))

        i = 0
        while i < len(items):
            chunk_items = items[i:i+3]

            combined_text = "\n\n".join([x["text"] for x in chunk_items])

            combined_metadata = {
                "year": year,
                "severity": severity,
                "cve_ids": [x["metadata"].get("cve_id") for x in chunk_items],
                "source": "NVD",
                "section": "cve_grouped"
            }

            base_chunk = {
                "chunk_id": f"cve_chunk_{chunk_id}",
                "text": combined_text,
                "metadata": combined_metadata
            }

            split_chunks = split_oversized(base_chunk)

            for ch in split_chunks:
                if len(ch["text"]) > MAX_CHARS:
                    final_chunks.extend(hard_cap_split(ch))
                else:
                    final_chunks.append(ch)

            chunk_id += 1
            i += 2  

    return final_chunks


def save_jsonl(data, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        for item in data:
            f.write(json.dumps(item) + "\n")


def main():
    all_data = []

    print("Loading CVE files...")
    for file in CVE_FILES:
        all_data.extend(load_jsonl(file))

    print(f"Total CVEs loaded: {len(all_data)}")

    print("Grouping CVEs (year + severity)...")
    grouped = group_cves(all_data)

    print("Creating chunks (3 CVEs + overlap)...")
    final_chunks = create_chunks(grouped)

    print(f"Final chunks after splitting: {len(final_chunks)}")

    print("Saving...")
    save_jsonl(final_chunks, OUTPUT_PATH)

    print(" Done!")


if __name__ == "__main__":
    main()