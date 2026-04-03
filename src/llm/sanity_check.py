# test.py
import time
from src.index.index_utils import HybridRetrievalSystem
system=HybridRetrievalSystem()
from  src.test.retrival_metric import score_results
from src.test.truth import GROUND_TRUTH  
from src.llm.client import _flatten_cve, _flatten_cwe, _call_gemini
from src.test.genration_metric import evaluate_answer, format_eval_report
from src.llm.prompt_temp import User_promt


#RETRIVAL
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
        
def retrevial_sanity(query,k_primary,k_secondary):
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
    return results_for_metrics



#Generation
def genrative_sanity(query,results_for_metrics):
    cve_block = _flatten_cve(results_for_metrics["cve_results"])
    cwe_block = _flatten_cwe(results_for_metrics["cve_results"])

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





def run_sanity_check():
    k_primary = 20
    k_secondary =16

    for i, (query, expected_keywords) in enumerate(GROUND_TRUTH.items(), 1):
        results_for_metrics=retrevial_sanity(query, k_primary, k_secondary)
        genrative_sanity(query,results_for_metrics)
        time.sleep(10)
    print("\nSanity check completed.\n")


if __name__ == "__main__":
    run_sanity_check()