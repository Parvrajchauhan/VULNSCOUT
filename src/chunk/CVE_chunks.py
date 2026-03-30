import json
import os
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


def hard_split(chunk_id_base, text, metadata):
    if len(text) <= MAX_CHARS:
        return [{
            "chunk_id":    chunk_id_base,
            "text":        text,
            "text_length": len(text),
            "metadata":    metadata
        }]

    parts = []
    for i, start in enumerate(range(0, len(text), MAX_CHARS)):
        part_text = text[start:start + MAX_CHARS]
        parts.append({
            "chunk_id":    f"{chunk_id_base}-pt{i+1}",
            "text":        part_text,
            "text_length": len(part_text),
            "metadata":    {**metadata, "part": i + 1}
        })

    return parts


def create_chunks(all_data):
    final_chunks = []

    # deduplicate by cve_id
    seen_ids = set()
    deduped  = []
    for item in all_data:
        cve_id = item.get("metadata", {}).get("cve_id", "")
        if cve_id and cve_id not in seen_ids:
            seen_ids.add(cve_id)
            deduped.append(item)
        elif not cve_id:
            deduped.append(item) 

    print(f"After dedup: {len(deduped)} CVEs (removed {len(all_data) - len(deduped)} duplicates)")

    for idx, item in enumerate(deduped, start=1):
        meta     = item.get("metadata", {})
        cve_id   = meta.get("cve_id", f"UNKNOWN-{idx}")
        year     = get_year(meta.get("published_date", ""))
        severity = meta.get("cvss_severity", "UNKNOWN")
        text     = item.get("text", "").strip()

        if not text:
            continue

        chunk_metadata = {
            "cve_id":   cve_id,
            "year":     year,
            "severity": severity,
            "source":   "NVD",
            "section":  "cve_single",
        }

        for extra_key in ("cvss_score", "published_date", "vendor", "product"):
            if extra_key in meta:
                chunk_metadata[extra_key] = meta[extra_key]

        chunks = hard_split(f"cve_{cve_id}", text, chunk_metadata)
        final_chunks.extend(chunks)

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
        chunk = load_jsonl(file)
        print(f"  {file}: {len(chunk)} records")
        all_data.extend(chunk)

    print(f"Total CVEs loaded: {len(all_data)}")

    print("Creating 1-CVE-per-chunk...")
    final_chunks = create_chunks(all_data)

    print(f"Final chunk count: {len(final_chunks)}")

    # quick stats
    lengths = [c["text_length"] for c in final_chunks]
    print(f"  Avg length : {sum(lengths)//len(lengths)} chars")
    print(f"  Max length : {max(lengths)} chars")
    print(f"  Over limit : {sum(1 for l in lengths if l > MAX_CHARS)} chunks")

    print("Saving")
    save_jsonl(final_chunks, OUTPUT_PATH)


if __name__ == "__main__":
    main()