# test.py

from src.index.index_utils import HybridRetrievalSystem


def run_sanity_check():
    system = HybridRetrievalSystem()

    test_queries1 = [
        # CWE-style (conceptual)
        "What is SQL injection and how to prevent it?",

        # CVE-style (real vulnerability)
        "CVE-2025-12707 vulnerability exploit and patch",

        # Mixed / ambiguous
        "buffer overflow vulnerability in C program example"
    ]
    test_queries2 = [
    # Path Traversal / LFI
    "directory traversal ../../../etc/passwd vulnerability",
    "access /etc/shadow via path traversal attack",

    # NoSQL Injection
    "NoSQL injection using filter[$ne]=null",
    "NoSQL injection using fields[$gt] operator",

    # Normal login (baseline)
    "multiple login requests brute force attempt",

    # Server-side injection / timing attack
    "NoSQL injection with $where sleep(5000) delay attack",

    # XSS attacks
    "XSS attack using <script>alert(document.cookie)</script>",
    "XSS attack using img onerror fetch exfiltration",

    # SQL Injection
    "SQL injection OR 1=1 bypass login",
    "SQL injection UNION SELECT username password",

    # NoSQL / JS injection
    "NoSQL injection using $where password match regex",

    # Command Injection
    "command injection ls -la /etc",
    "command injection cat /etc/passwd",

    # File inclusion / LFI
    "php filter base64 encode file read /etc/passwd",

    # SSRF
    "SSRF attack to AWS metadata 169.254.169.254",

    # Windows path traversal
    "directory traversal ../../boot.ini windows"
]

    k_primary = 20
    k_secondary = 10

    for i, query in enumerate(test_queries2, 1):
        print(f" Test Query {i}: {query}")
       

        response = system.query(query, k_primary, k_secondary)

        print(f"\n Route Decision: {response['route']}")

        results = response["results"]
        cve_results = results.get("cve_results", [])
        cwe_results = results.get("cwe_results", [])

        print(f"\n Top CVE Results ({len(cve_results)}):\n")

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

    print("\nSanity check completed.\n")


if __name__ == "__main__":
    run_sanity_check()