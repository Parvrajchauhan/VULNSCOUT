# api/core/generator.py
import re
import time
from src.llm.client import user_query, waf_analysis
from api.schemas import QueryResponse

def _clean_answer(text: str) -> str:
    text = re.sub(r'\*\*(.*?)\*\*', r'\1', text)   
    text = re.sub(r'\*(.*?)\*', r'\1', text)       
    text = re.sub(r'^#{1,6}\s*', '', text, flags=re.MULTILINE) 
    text = re.sub(r'\n{3,}', '\n\n', text)         
    text = text.strip()
    return text

def _parse_sections(text: str) -> dict:
    fields = {
        "answer":           r"Answer:\s*(.*?)(?=\nCVE references:|\nCWE references:|\nOWASP references:|\nConfidence:|\nContext gap:|$)",
        "cve_references":   r"CVE references:\s*(.*?)(?=\nCWE references:|\nOWASP references:|\nConfidence:|\nContext gap:|$)",
        "cwe_references":   r"CWE references:\s*(.*?)(?=\nOWASP references:|\nConfidence:|\nContext gap:|$)",
        "owasp_references": r"OWASP references:\s*(.*?)(?=\nConfidence:|\nContext gap:|$)",
        "confidence":       r"Confidence:\s*(.*?)(?=\nContext gap:|$)",
        "context_gap":      r"Context gap:\s*(.*?)$",
    }
    result = {}
    for key, pattern in fields.items():
        match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        result[key] = match.group(1).strip() if match else None
    return result

def generate(request) -> QueryResponse:
    t1 = time.perf_counter()

    if request.type == "user":
        if not request.query:
            raise ValueError("query field required for type='user'")
        answer = user_query(request.query)

    elif request.type == "waf":
        if not request.waf_data:
            raise ValueError("waf_data field required for type='waf'")
        d = request.waf_data
        answer = waf_analysis(
            http_method=d.http_method,
            request_path=d.request_path,
            query_string=d.query_string,
            body_snippet=d.body_snippet,
            anomaly_tokens=d.anomaly_tokens,
            pll_score=d.pll_score,
            threshold=d.threshold,
        )
    else:
        raise ValueError(f"Unknown request type: {request.type!r}")

    latency = (time.perf_counter() - t1) * 1000

    cleaned  = _clean_answer(answer)
    sections = _parse_sections(cleaned)

    return QueryResponse(
        answer=sections.get("answer") or cleaned,
        cve_references=sections.get("cve_references"),
        cwe_references=sections.get("cwe_references"),
        owasp_references=sections.get("owasp_references"),
        confidence=sections.get("confidence"),
        context_gap=sections.get("context_gap"),
        latency_ms=round(latency, 2),
    )