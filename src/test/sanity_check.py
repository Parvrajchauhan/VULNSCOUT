# test.py
import time
from src.index.index_utils import HybridRetrievalSystem
system = HybridRetrievalSystem()
from src.test.retrival_metric import score_results
from src.test.truth import GROUND_TRUTH
from src.llm.client import _flatten_cve, _flatten_cwe, _call_gemini
from src.test.genration_metric import evaluate_answer, format_eval_report
from src.llm.prompt_temp import User_promt


def _print_retrieval_metrics(ret_scores: dict):
    print("  Retrieval Metrics")
    print(f"  {'Recall':<20} {ret_scores['recall']:.3f}")
    print(f"  {'MRR':<20} {ret_scores['mrr']:.3f}")


def _print_hit_summary(results_for_metrics: dict):
    cve_hits = results_for_metrics.get("cve_results", [])
    cwe_hits = results_for_metrics.get("cwe_results", [])
    route    = results_for_metrics.get("route", "user_query")

    print(f"  Route          : {route}")
    print(f"  CVE hits       : {len(cve_hits)}")
    print(f"  CWE hits       : {len(cwe_hits)}")

    if cve_hits:
        meta  = cve_hits[0].get("data", {}).get("metadata", {})
        tag   = meta.get("cve_id", meta.get("id", "?"))
        score = cve_hits[0].get("score", "?")
        print(f"  Top CVE chunk  : {tag}  (score {score})")
    if cwe_hits:
        meta  = cwe_hits[0].get("data", {}).get("metadata", {})
        tag   = meta.get("id", meta.get("cwe_id", "?"))
        score = cwe_hits[0].get("score", "?")
        print(f"  Top CWE chunk  : {tag}  (score {score})")


def retrevial_sanity(query, k_primary, k_secondary):
    print(f" Test Query: {query}")

    t0 = time.perf_counter()
    response = system.query(query, k_primary, k_secondary)
    retrieval_time = time.perf_counter() - t0

    inner       = response.get("results", response)
    cve_results = inner.get("cve_results", [])
    cwe_results = inner.get("cwe_results", [])

    results_for_metrics = {
        "cve_results": cve_results,
        "cwe_results": cwe_results,
        "route":       response.get("route", "user_query"),
    }

    _print_hit_summary(results_for_metrics)
    print(f"  Retrieval time : {retrieval_time:.2f}s")

    ret_scores = score_results(query, results_for_metrics)
    _print_retrieval_metrics(ret_scores)
    return results_for_metrics, ret_scores



def genrative_sanity(query, results_for_metrics):
    cve_block = _flatten_cve(results_for_metrics["cve_results"])
    cwe_block = _flatten_cwe(results_for_metrics["cwe_results"])

    prompt = User_promt.format(
        cve_context=cve_block,
        cwe_context=cwe_block,
        user_question=query,
    )

    t1     = time.perf_counter()
    answer = _call_gemini(prompt)
    gen_time = time.perf_counter() - t1

    print("  Generated Answer")
    for line in answer.strip().splitlines():
        print(f"  {line}")
    print(f"\n  Generation time : {gen_time:.2f}s")

    t2          = time.perf_counter()
    eval_result = evaluate_answer(query, answer, results_for_metrics)
    judge_time  = time.perf_counter() - t2

    print(format_eval_report(eval_result))
    print(f"  Judge time     : {judge_time:.2f}s")

    return eval_result

def _print_summary(all_results: list[dict]):
    n = len(all_results)
    if not n:
        return

    keys_ret = ["recall", "mrr"]
    keys_gen = ["groundedness", "hallucination_penalty",
                "citation_correctness", "relevance", "overall"]

    totals = {k: 0.0 for k in keys_ret + keys_gen}

    for r in all_results:
        for k in keys_ret:
            totals[k] += r["retrieval"][k]
        for k in keys_gen:
            if k == "overall":
                totals[k] += r["generative"].get("overall", 0)
            else:
                totals[k] += r["generative"].get(k, {}).get("score", 0)

    sep = "─" * 52
    print(f"\n{'═' * 52}")
    print("  AVERAGE SCORES ACROSS ALL QUERIES")
    print(f"{'═' * 52}")
    print(f"  {'Metric':<30} {'Avg':>8}")
    print(sep)
    for k in keys_ret:
        print(f"  {k.replace('_', ' ').title():<30} {totals[k]/n:>8.3f}")
    print(sep)
    for k in keys_gen:
        label = k.replace("_", " ").title()
        val   = totals[k] / n
        fmt   = f"{val:>8.3f}" if k == "overall" else f"{val:>8.1f}/10"
        print(f"  {label:<30} {fmt}")
    print(f"{'═' * 52}\n")



def run_sanity_check():
    k_primary   = 20
    k_secondary = 16

    all_results = []

    for query in GROUND_TRUTH:
        results_for_metrics, ret_scores = retrevial_sanity(query, k_primary, k_secondary)
        eval_result = genrative_sanity(query, results_for_metrics)

        all_results.append({
            "query":      query,
            "retrieval":  ret_scores,
            "generative": eval_result,
        })

        time.sleep(10)

    _print_summary(all_results)
    print("\nSanity check completed.\n")


if __name__ == "__main__":
    run_sanity_check()