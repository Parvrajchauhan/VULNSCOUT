import os
import re
import json

INPUT_DIR = "data/raw/OWASP/Top10/2025/docs/en"
OUTPUT_FILE = "data/raw/OWASP/Top10_json/owasp_top10_2025.json"

os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)



def clean_markdown(text):
    # remove images
    text = re.sub(r'!\[.*?\]\(.*?\)', '', text)
    # remove HTML-style attributes like {: ...}
    text = re.sub(r'\{\:.*?\}', '', text)

    # remove links but keep text
    text = re.sub(r'\[(.*?)\]\(.*?\)', r'\1', text)
    text = re.sub(r'https?://\S+', '', text)

    # remove bold/italic
    text = re.sub(r'\*\*(.*?)\*\*', r'\1', text)
    text = re.sub(r'\*(.*?)\*', r'\1', text)

    # remove inline code
    text = text.replace("`", "")
    

    # remove bullet points
    text = re.sub(r'^\s*[-*]\s+', '', text, flags=re.MULTILINE)

    # remove CWE mentions (optional but recommended)
    text = re.sub(r'CWE-\d+[^.,\n]*', '', text)

    # normalize spaces
    text = re.sub(r'\n+', '\n', text)
    text = re.sub(r'\s+', ' ', text)

    return text.strip()


def remove_unwanted_sections(text):
    # remove score tables
    text = re.sub(r'## Score table.*?(?=##|\Z)', '', text, flags=re.S)

    # remove references
    text = re.sub(r'## References.*?(?=##|\Z)', '', text, flags=re.S)

    # remove CWE list
    text = re.sub(r'## List of Mapped CWEs.*?(?=##|\Z)', '', text, flags=re.S)

    return text


def normalize_section_title(title):
    title = title.replace(".", "").strip().title()

    mapping = {
        "Background": "Overview",
        "Description": "Description",
        "How To Prevent": "How to Prevent",
        "Example Attack Scenarios": "Example Attack Scenarios"
    }

    return mapping.get(title, title)


def get_section_label(section_name):
    section_name = section_name.lower()

    if "prevent" in section_name:
        return "mitigation_guide"
    elif "example" in section_name:
        return "attack_example"
    else:
        return "attack_category"



def parse_file(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    content = remove_unwanted_sections(content)

    # Extract title
    title_match = re.search(r'#\s*(A\d{2}:\d{4})\s*(.*)', content)
    if not title_match:
        return []

    owasp_id = title_match.group(1)

    # CLEAN category name
    
    raw_category = title_match.group(2)

    category_name = re.sub(r'!\[.*?\]\(.*?\)', '', raw_category)
    category_name = re.sub(r'\{\:.*?\}', '', category_name)   # ADD THIS
    category_name = category_name.strip()


    # Split sections
    sections = re.split(r'\n##\s+', content)

    chunks = []

    for sec in sections:
        if len(sec.strip()) < 50:
            continue

        lines = sec.strip().split("\n")
        section_title_raw = lines[0].strip()
        section_title = normalize_section_title(section_title_raw)

        section_text = "\n".join(lines[1:]).strip()

        # Skip useless sections
        if section_title.lower() in [
            "references",
            "score table",
            "list of mapped cwes"
        ]:
            continue

        section_text = clean_markdown(section_text)

        if len(section_text) < 80:
            continue

        section_label = get_section_label(section_title)

        embedding_text = (
            f"OWASP {owasp_id} – {category_name} | "
            f"{section_title}: {section_text}"
        )

        chunk = {
            "text": embedding_text,
            "metadata": {
                "owasp_id": owasp_id,
                "category_name": category_name,
                "section": section_title,
                "section_type": section_label,
                "source": "OWASP Top 10 2025"
            }
        }

        chunks.append(chunk)

    return chunks



def main():
    all_chunks = []

    for filename in os.listdir(INPUT_DIR):
        if not filename.startswith("A"):
            continue

        filepath = os.path.join(INPUT_DIR, filename)
        chunks = parse_file(filepath)
        all_chunks.extend(chunks)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(all_chunks, f, indent=2, ensure_ascii=False)

    print(f" Total chunks: {len(all_chunks)}")
    print(f" Saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()