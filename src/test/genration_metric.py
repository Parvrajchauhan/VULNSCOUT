import json
import re
import os
from google import genai
from google.genai import types
from dotenv import load_dotenv
load_dotenv()
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
Model = os.getenv("GEMINI_MODEL")


def extract_context(results):
    context = ""
    for r in results.get("cve_results", []) + results.get("cwe_results", []):
        data     = r.get("data", {})
        text     = data.get("text", "")
        metadata = data.get("metadata", {})

        # CVE chunks use "cve_id"; CWE chunks use "id" (not "cwe_id")
        tag = metadata.get("cve_id") or metadata.get("id") or "UNKNOWN"
        context += f"[{tag}] {text}\n\n"

    return context.strip()


_JUDGE_PROMPT = """\
You are a strict cybersecurity RAG evaluator. You will score an AI-generated \
answer across four dimensions. Be rigorous: a confident wrong answer is worse \
than an honest "I don't know."

QUERY
{query}

RETRIEVED CONTEXT
{context}

ANSWER UNDER EVALUATION
{answer}

Score each dimension from 1 (worst) to 10 (best) and give a one-sentence
reason. Then give an overall weighted score.

DIMENSIONS

1. groundedness (weight 0.35)
   Every factual claim in the answer must trace back to the context above.
   Penalise any claim that has no supporting sentence in context, even if
   the claim is generally true in the real world.

2. hallucination_penalty (weight 0.30)
   Specifically check for invented identifiers:
     - CVE IDs (CVE-YYYY-NNNNN) that do NOT appear in context
     - CWE numbers (CWE-NNN) that do NOT appear in context
     - CVSS scores that differ from what context states
   Score 10 = zero invented identifiers. Score 1 = multiple invented IDs.

3. citation_correctness (weight 0.20)
   If the answer cites sources (e.g. "According to CVE-2024-1234" or
   "CWE-89 states..."), check that those citations actually appear in
   context and that the cited content matches what context says.
   Score 10 = all citations correct or no citations used.
   Score 1 = answer attributes claims to wrong/absent sources.

4. relevance (weight 0.15)
   Does the answer directly address the query?
   Is it complete without padding?
   Is the cybersecurity reasoning sound?

OUTPUT FORMAT — return ONLY valid JSON, no markdown fences, no extra text:
{{
  "groundedness":          {{"score": <1-10>, "reason": "<one sentence>"}},
  "hallucination_penalty": {{"score": <1-10>, "reason": "<one sentence>"}},
  "citation_correctness":  {{"score": <1-10>, "reason": "<one sentence>"}},
  "relevance":             {{"score": <1-10>, "reason": "<one sentence>"}},
  "overall":               <weighted float, 1 decimal place>
}}
"""

def _build_judge_prompt(query, answer, context):
    return _JUDGE_PROMPT.format(
        query=query,
        context=context if context else "(no context retrieved)",
        answer=answer,
    )


def _parse_judge_response(raw):
    clean = raw.strip()
    clean = re.sub(r'^```(?:json)?\s*', '', clean)
    clean = re.sub(r'\s*```$', '', clean)

    try:
        parsed = json.loads(clean)
    except json.JSONDecodeError:
        match = re.search(r'\{.*\}', clean, re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group())
            except json.JSONDecodeError:
                return _error_response("JSON parse failed after fallback")
        else:
            return _error_response("No JSON object found in response")

    required = {"groundedness", "hallucination_penalty",
                "citation_correctness", "relevance", "overall"}
    if not required.issubset(parsed.keys()):
        return _error_response(f"Missing keys: {required - parsed.keys()}")

    return parsed


def _error_response(reason):
    empty = {"score": 0.0, "reason": reason}
    return {
        "groundedness":          empty,
        "hallucination_penalty": empty,
        "citation_correctness":  empty,
        "relevance":             empty,
        "overall":               0.0,
        "_error":                reason,
    }


def _call_gemini(prompt: str) -> str:
    try:
        response = client.models.generate_content(
            model=Model,
            contents=prompt
        )
        return response.text
    except Exception as e:
        return f"Error: {str(e)}"
    

def evaluate_answer(query, answer, results):
    context = extract_context(results)
    prompt  = _build_judge_prompt(query, answer, context)

    raw      = _call_gemini(prompt)
    scores   = _parse_judge_response(raw)

    scores["context_used"] = context
    return scores


def format_eval_report(eval_result):
    if "_error" in eval_result:
        return f"[EVAL ERROR] {eval_result['_error']}"

    dims = ["groundedness", "hallucination_penalty",
            "citation_correctness", "relevance"]

    lines = "  LLM Judge Evaluation Report"
    for dim in dims:
        d = eval_result[dim]
        label = dim.replace("_", " ").title()
        lines.append(f"  {label:<26} {d['score']:>4}/10")
        lines.append(f"    → {d['reason']}")
    lines.append(f"  {'Overall (weighted)':<26} {eval_result['overall']:>4}/10")
    return "\n".join(lines)