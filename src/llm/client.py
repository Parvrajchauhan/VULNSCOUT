import os
from google import genai
from google.genai import types
from dotenv import load_dotenv
from src.llm.prompt_temp import System_promt, WAF_promt, User_promt
from src.index.index_utils import HybridRetrievalSystem
load_dotenv()
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
Model = os.getenv("GEMINI_MODEL")
retriever = HybridRetrievalSystem()


def _flatten_cve(cve_results: list) -> str:
    if not cve_results:
        return "No CVE context retrieved."

    lines = []
    for r in cve_results:
        meta = r["data"]["metadata"]          
        text = r["data"].get("text", "")       
        cve_id   = meta.get("cve_id",       "N/A")
        severity = meta.get("severity",     "N/A")
        cvss     = meta.get("cvss_score",   "N/A")
        year     = meta.get("year",         "")
        pub_date = meta.get("published_date", "")

        lines.append(
            f"{cve_id} | Severity: {severity} | CVSS: {cvss} | "
            f"Published: {pub_date or year}\n"
            f"  {text}"
        )

    return "\n".join(lines)

def _flatten_cwe(cwe_results):
    lines = []
    for r in cwe_results:
        meta   = r["data"]["metadata"]
        text   = r["data"].get("text", "")
        entry_id = meta.get("id", "N/A")
        source   = meta.get("source", "CWE").upper()
        lines.append(f"[{source}] {entry_id}: {text}")
    return "\n\n".join(lines) if lines else "No CWE/OWASP context retrieved."

def _call_gemini(prompt: str) -> str:
    try:
        response = client.models.generate_content(
            model=Model,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=System_promt
            ),
        )
        return response.text
    except Exception as e:
        return f"Error: {str(e)}"


def _retrieve_contexts(query_text: str) -> tuple[str, str, str]:
    result      = retriever.query(query_text)
    cve_block   = _flatten_cve(result["results"]["cve_results"])
    cwe_owasp_block = _flatten_cwe(result["results"]["cwe_results"])
    return cve_block, cwe_owasp_block


def waf_analysis(
    http_method: str,
    request_path: str,
    query_string: str,
    body_snippet: str,
    anomaly_tokens: list,
    pll_score: float,
    threshold: float,
) -> str:
    
    retrieval_query = f"{request_path} {query_string} {' '.join(anomaly_tokens)}"
    cve_context, cwe_owasp_block = _retrieve_contexts(retrieval_query)

    prompt = WAF_promt.format(
        cve_context=cve_context,
        cwe_context=cwe_owasp_block,
        http_method=http_method,
        request_path=request_path,
        query_string=query_string,
        body_snippet=body_snippet if body_snippet else "None",
        anomaly_tokens=anomaly_tokens,
        pll_score=pll_score,
        threshold=threshold,
    )
    return _call_gemini(prompt)


def user_query(
    user_question: str,
) -> str:
    print(f"  QUERY: {user_question}")
    
    cve_context, cwe_owasp_block = _retrieve_contexts(user_question)

    prompt = User_promt.format(
        cve_context=cve_context,
        cwe_context=cwe_owasp_block,
        user_question=user_question,
    )
    
    return _call_gemini(prompt)


if __name__ == "__main__":
    print("=== USER QUERY ===")
    res1 = user_query("buffer overflow vulnerability in C program example")
    print(res1)

    print("\n=== WAF ANALYSIS ===")
    res2 = waf_analysis(
        http_method="GET",
        request_path="directory traversal ../../../etc/passwd ",
        query_string="vulnerability",
        body_snippet="",
        anomaly_tokens=["OR '1'='1"],
        pll_score=0.92,
        threshold=0.8,
    )
    print(res2)