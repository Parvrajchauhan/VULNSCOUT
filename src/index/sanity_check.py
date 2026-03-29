# test.py

from src.index.index_utils import HybridRetrievalSystem


def run_sanity_check():
    system = HybridRetrievalSystem()

    test_queries = [
        # CWE-style (conceptual)
        "What is SQL injection and how to prevent it?",

        # CVE-style (real vulnerability)
        "CVE-2025-12707 vulnerability exploit and patch",

        # Mixed / ambiguous
        "buffer overflow vulnerability in C program example"
    ]

    k_primary = 20
    k_secondary = 10

    for i, query in enumerate(test_queries, 1):
        print(f" Test Query {i}: {query}")
       

        response = system.query(query, k_primary, k_secondary)

        print(f"\n🧭 Route Decision: {response['route']}")

        results = response["results"]

        cve_results = results.get("cve_results", [])
        cwe_results = results.get("cwe_results", [])

        print(f"\n📌 Top CVE Results ({len(cve_results)}):\n")

        for rank, result in enumerate(cve_results, 1):
            score = result.get("score", 0)
            data = result.get("data", {})
            preview = str(data.get("text", ""))[:120].replace("\n", " ")

            print(f"{rank:02d}. [CVE] Score: {score:.4f}")
            print(f"    → {preview}...\n")

        print(f"\n Top CWE/OWASP Results ({len(cwe_results)}):\n")

        for rank, result in enumerate(cwe_results, 1):
            score = result.get("score", 0)
            data = result.get("data", {})
            source = data.get("metadata", {}).get("source", "UNKNOWN")

            preview = str(data.get("text", ""))[:120].replace("\n", " ")

            print(f"{rank:02d}. [{source}] Score: {score:.4f}")
            print(f"    → {preview}...\n")

    print("\n✅ Sanity check completed.\n")


if __name__ == "__main__":
    run_sanity_check()