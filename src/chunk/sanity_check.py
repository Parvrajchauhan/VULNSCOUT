import json
import os
import pandas as pd


FILES = {
    "CVE": "data/chunkfile/cve_chunks.jsonl",
    "CWE_OWASP": "data/chunkfile/cwe_owasp_chunks.jsonl"
}


def load_jsonl(file_path):
    data = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            data.append(json.loads(line))
    return data


def normalize_data(data):
    rows = []

    for item in data:
        metadata = item.get("metadata", {})

        rows.append({
            "chunk_id": item.get("chunk_id"),
            "text": item.get("text", ""),
            "text_length": len(item.get("text", "")),
            "source": metadata.get("source"),
            "section": metadata.get("section"),
            "section_type": metadata.get("section_type"),
            "severity": metadata.get("severity"),
            "year": metadata.get("year")
        })

    return pd.DataFrame(rows)


def analyze(df, name):
    print(f" DATASET ANALYSIS: {name}")

    print(f"\nTotal Chunks: {len(df)}")

    print("\nColumns:")
    print(df.columns.tolist())

    print("\nText Length Stats:")
    print(f"Avg Length: {df['text_length'].mean():.2f}")
    print(f"Max Length: {df['text_length'].max()}")
    print(f"Min Length: {df['text_length'].min()}")

    print("\nUnique Sources:")
    print(df["source"].dropna().unique())

    print("\nSource Distribution:")
    print(df["source"].value_counts())

    print("\nUnique Sections:")
    print(df["section"].dropna().unique())

    print("\nSection Distribution:")
    print(df["section"].value_counts())

    if df["section_type"].notna().any():
        print("\nSection Type Distribution:")
        print(df["section_type"].value_counts())

    if df["severity"].notna().any():
        print("\nSeverity Distribution:")
        print(df["severity"].value_counts())

    if df["year"].notna().any():
        print("\nYear Distribution:")
        print(df["year"].value_counts().sort_index())

    print("\nMissing Values:")
    print(df.isnull().sum())

    print("\nDuplicate Chunks (by text):")
    print(df.duplicated(subset=["text"]).sum())

    print("\nChunk Size Distribution:")
    print(pd.cut(df["text_length"], bins=[0,300,600,900,1200,2000,5000]).value_counts().sort_index())

    print("\nAnalysis Complete!")


def main():
    for name, path in FILES.items():
        print(f"\nLoading {name}...")
        data = load_jsonl(path)

        df = normalize_data(data)
        analyze(df, name)


if __name__ == "__main__":
    main()