import xml.etree.ElementTree as ET
import json

NS = "http://cwe.mitre.org/cwe-7"

def get_text(el, tag):
    node = el.find(f"{{{NS}}}{tag}")
    return node.text.strip() if node is not None and node.text else ""

def get_all_text(el, path):
    return " ".join(
        n.text.strip() for n in el.findall(f".//{{{NS}}}{path}") if n.text
    )

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

        desc     = get_text(w, "Description")
        ext_desc = get_text(w, "Extended_Description")

        base_meta = {
            "cwe_id": cwe_id,
            "cwe_name": name,
            "abstraction": abstraction,
            "source": "MITRE CWE"
        }

        consequences = []
        for c in w.findall(f".//{{{NS}}}Consequence"):
            scope  = get_all_text(c, "Scope")
            impact = get_all_text(c, "Impact")
            consequences.append(f"{scope} → {impact}".strip())

        consequences_text = " | ".join(consequences)

        text = f"{cwe_id}: {name}. {desc} {ext_desc}"
        if consequences_text:
            text += f" Consequences: {consequences_text}"

        chunks.append({
            "text": text.strip(),
            "metadata": {**base_meta, "section": "weakness_detail"}
        })

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
                "text": f"{cwe_id}: {name} — Mitigation. {' | '.join(mitigations)}",
                "metadata": {**base_meta, "section": "mitigation_guide"}
            })

        examples = []

        for ex in w.findall(f".//{{{NS}}}Demonstrative_Example"):
            intro = get_all_text(ex, "Intro_Text")
            body  = get_all_text(ex, "Body_Text")

            # Code snippets
            code = []
            for snippet in ex.findall(f".//{{{NS}}}Example_Code"):
                code_text = snippet.text.strip() if snippet.text else ""
                if code_text:
                    code.append(code_text)

            example_text = f"{intro} {body} {' '.join(code)}".strip()

            if example_text:
                examples.append(example_text)

        if examples:
            chunks.append({
                "text": f"{cwe_id}: {name} — Examples. {' | '.join(examples)}",
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