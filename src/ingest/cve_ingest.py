import json

INPUT_FILE = "data/raw/NVD_CVE/nvdcve-2.0-2026.json"
OUTPUT_FILE = "data/raw/NVD_CVE/cve_processed1.jsonl"


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


#  FILTER FUNCTION (ALL RULES HERE)
def is_valid_cve(description, cvss_score):
    if not description:
        return False

    desc_lower = description.lower()

    #  Reject invalid CVEs
    if "rejected" in desc_lower or "reserved" in desc_lower:
        return False

    #  Too short (low quality)
    if len(description.strip()) < 20:
        return False

    #  No severity info
    if cvss_score is None:
        return False

    return True


def process_cve(item):
    cve = item.get("cve", {})

    cve_id = cve.get("id")
    description = get_english_description(cve.get("descriptions", []))

    cvss = extract_cvss(cve.get("metrics", {}))

    # 🔥 Apply filters EARLY
    if not is_valid_cve(description, cvss["score"]):
        return None

    cwe_id = extract_cwe(cve.get("weaknesses", []))

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

    print(f"Total CVEs (raw): {len(items)}")

    kept = 0
    skipped = 0

    with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
        for item in items:
            try:
                processed = process_cve(item)

                if processed is None:
                    skipped += 1
                    continue

                out.write(json.dumps(processed) + "\n")
                kept += 1

            except Exception as e:
                skipped += 1
                print(f"Error processing CVE: {e}")

    print(f"Kept: {kept}")
    print(f"Skipped: {skipped}")
    print(f"Saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()