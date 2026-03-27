import json
from datetime import datetime

INPUT_FILE = "data/nvdcve-2.0-recent.json"
OUTPUT_FILE = "data/raw/cve_processed.jsonl"


def get_english_description(descriptions):
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def extract_cwe(weaknesses):
    try:
        return weaknesses[0]["description"][0]["value"]
    except:
        return None


def extract_cvss(metrics):
    try:
        cvss = metrics["cvssMetricV31"][0]["cvssData"]
        return {
            "score": cvss.get("baseScore"),
            "severity": cvss.get("baseSeverity"),
            "attack_vector": cvss.get("attackVector")
        }
    except:
        return {
            "score": None,
            "severity": None,
            "attack_vector": None
        }


def process_cve(item):
    cve = item.get("cve", {})

    cve_id = cve.get("id")
    description = get_english_description(cve.get("descriptions", []))
    cwe_id = extract_cwe(cve.get("weaknesses", []))
    cvss = extract_cvss(cve.get("metrics", {}))

    published = cve.get("published", "")
    published_date = published.split("T")[0] if published else None

    text = f"{cve_id}: {description}"

    metadata = {
        "cve_id": cve_id,
        "cwe_id": cwe_id,
        "cvss_score": cvss["score"],
        "cvss_severity": cvss["severity"],
        "attack_vector": cvss["attack_vector"],
        "published_date": published_date,
        "source": "NVD",
        "section": "cve_description"
    }

    return {
        "text": text,
        "metadata": metadata
    }


def main():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    items = data.get("vulnerabilities", [])

    print(f"Total CVEs: {len(items)}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
        for item in items:
            try:
                processed = process_cve(item)
                out.write(json.dumps(processed) + "\n")
            except Exception as e:
                print(f"Error processing CVE: {e}")

    print(f" Done! Saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()