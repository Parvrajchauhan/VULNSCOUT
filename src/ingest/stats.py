import pandas as pd
from pathlib import Path


def analyze_csv(file_path):
    print(file_path)
    file_path = Path(file_path)

    if file_path.suffix == ".json":
        df= pd.read_json(file_path)

    elif file_path.suffix == ".jsonl":
        df= pd.read_json(file_path, lines=True)
    

    print("DATASET ANALYSIS")

    # Basic stats
    total_rows = len(df)
    print(f"Total Rows: {total_rows}")
    print(f"Total Chunks: {total_rows}")

    print("\nColumns:")
    print(list(df.columns))

    if "metadata" in df.columns:
        df["section"] = df["metadata"].apply(
            lambda x: x.get("section") if isinstance(x, dict) else None
        )
        df["source"] = df["metadata"].apply(
            lambda x: x.get("source") if isinstance(x, dict) else None
        )

    # Sections
    if "section" in df.columns:
        sections = df["section"].dropna().unique().tolist()
        print("\nUnique Sections:")
        print(sections)

        print("\nSection Distribution:")
        print(df["section"].value_counts())

    #  Sources
    if "source" in df.columns:
        sources = df["source"].dropna().unique().tolist()
        print("\nUnique Sources:")
        print(sources)

        print("\nSource Distribution:")
        print(df["source"].value_counts())

    # CWE IDs
    if "cwe_id" in df.columns:
        unique_cwe = df["cwe_id"].dropna().unique()
        print(f"\nUnique CWE IDs: {len(unique_cwe)}")

    # Text stats
    if "text" in df.columns:
        df["text_length"] = df["text"].astype(str).apply(len)

        print("\nText Length Stats:")
        print(f"Avg Length: {df['text_length'].mean():.2f}")
        print(f"Max Length: {df['text_length'].max()}")
        print(f"Min Length: {df['text_length'].min()}")

    # Missing values
    print("\nMissing Values:")
    print(df.isnull().sum())

    # Duplicate check (safe)
    if "text" in df.columns:
        duplicates = df["text"].duplicated().sum()
    else:
        duplicates = 0

    print(f"\nDuplicate Rows: {duplicates}")

    print("\nAnalysis Complete!")


if __name__ == "__main__":
    arr=["data/raw/OWASP/Top10_json/owasp_top10_2025.json","data/raw/NVD_CVE/cve_processed1.jsonl","data/raw/NVD_CVE/cve_processed2.jsonl","data/raw/CWE/cwe_chunks.json"]
    for i in arr:
        analyze_csv(i)