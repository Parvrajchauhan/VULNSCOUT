import xml.etree.ElementTree as ET
import json
import re

NS = "http://cwe.mitre.org/cwe-7"

def get_text(el, tag):
    node = el.find(f"{{{NS}}}{tag}")
    return node.text.strip() if node is not None and node.text else ""

def get_all_text(el, path):
    return " ".join(
        n.text.strip() for n in el.findall(f".//{{{NS}}}{path}") if n.text
    )

def get_all_text_recursive(el):
    """Recursively extract all text from an element and its children."""
    parts = []
    if el.text and el.text.strip():
        parts.append(el.text.strip())
    for child in el:
        parts.append(get_all_text_recursive(child))
        if child.tail and child.tail.strip():
            parts.append(child.tail.strip())
    return " ".join(p for p in parts if p)

def clean_code(raw: str) -> str:
    """Normalize code text: fix escaped quotes, collapse extra whitespace."""
    cleaned = raw.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("&quot;", '"').replace("&#39;", "'")
    cleaned = cleaned.replace('\\"', '"').replace("\\'", "'")
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
    return cleaned

def short_header(cwe_id: str, name: str) -> str:
    """Return a compact header: CWE-XXXX (Name)."""
    return f"{cwe_id} ({name})"

def parse_cwe(xml_path, out_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()

    chunks = []
    skipped = 0

    for w in root.findall(f".//{{{NS}}}Weakness"):

        abstraction = w.get("Abstraction", "")
        if abstraction not in ["Base", "Variant"]:
            skipped += 1
            continue

        cwe_id = f"CWE-{w.get('ID')}"
        name   = w.get("Name", "")
        header = short_header(cwe_id, name)

        desc     = get_text(w, "Description")
        ext_desc = get_text(w, "Extended_Description")

        base_meta = {
            "cwe_id": cwe_id,
            "cwe_name": name,
            "abstraction": abstraction,
            "source": "MITRE CWE"
        }

        # ── Consequences: include Note text alongside scope/impact ──
        consequences = []
        for c in w.findall(f".//{{{NS}}}Consequence"):
            scope  = get_all_text(c, "Scope")
            impact = get_all_text(c, "Impact")
            note   = get_all_text(c, "Note")
            entry  = f"{scope} → {impact}".strip()
            if note:
                entry += f" ({note})"
            consequences.append(entry)

        consequences_text = " | ".join(consequences)

        text = f"{header}: {desc} {ext_desc}"
        if consequences_text:
            text += f" Consequences: {consequences_text}"

        chunks.append({
            "text": text.strip(),
            "metadata": {**base_meta, "section": "weakness_detail"}
        })

        # ── Mitigations ──
        mitigations = []

        for m in w.findall(f".//{{{NS}}}Mitigation"):
            desc = get_all_text(m, "Description")
            eff  = get_all_text(m, "Effectiveness")
            note = get_all_text(m, "Effectiveness_Notes")

            m_text = desc
            if eff:
                m_text += f" (Effectiveness: {eff})"
            if note:
                m_text += f" Notes: {note}"

            if m_text:
                mitigations.append(m_text.strip())

        if mitigations:
            chunks.append({
                "text": f"{header} — Mitigation. {' | '.join(mitigations)}",
                "metadata": {**base_meta, "section": "mitigation_guide"}
            })

        # ── Demonstrative Examples ──
        examples = []

        for ex in w.findall(f".//{{{NS}}}Demonstrative_Example"):
            intro = get_all_text(ex, "Intro_Text")
            body  = get_all_text(ex, "Body_Text")

            # Code snippets — labeled and cleaned
            code = []
            for snippet in ex.findall(f".//{{{NS}}}Example_Code"):
                nature   = snippet.get("Nature", "")
                language = snippet.get("Language", "")
                raw_text = get_all_text_recursive(snippet)
                code_text = clean_code(raw_text)
                if code_text:
                    label = f"[{nature} - {language}]" if nature or language else ""
                    code.append(f"{label}\n{code_text}" if label else code_text)

            example_text = f"{intro} {body} {' '.join(code)}".strip()

            if example_text:
                examples.append(example_text)

        if examples:
            chunks.append({
                "text": f"{header} — Examples. {' | '.join(examples)}",
                "metadata": {**base_meta, "section": "attack_example"}
            })

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(chunks, f, indent=2, ensure_ascii=False)

    print(f"Done!")
    print(f"Chunks: {len(chunks)}")
    print(f"Skipped: {skipped}")
    print(f"Saved to: {out_path}")


if __name__ == "__main__":
    parse_cwe(
        xml_path="data/raw/CWE/cwec_v4.19.1.xml",
        out_path="data/raw/CWE/cwe_chunks.json"   
    )