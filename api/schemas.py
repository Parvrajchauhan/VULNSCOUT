# api/schemas.py
from pydantic import BaseModel
from typing import List, Optional

class WAFInput(BaseModel):
    http_method: str
    request_path: str
    query_string: str
    body_snippet: str
    anomaly_tokens: List[str]
    pll_score: float
    threshold: float

class QueryRequest(BaseModel):
    type: str
    query: Optional[str] = None
    waf_data: Optional[WAFInput] = None

class QueryResponse(BaseModel):
    answer: str
    cve_references: Optional[str] = None
    cwe_references: Optional[str] = None
    owasp_references: Optional[str] = None
    confidence: Optional[str] = None
    context_gap: Optional[str] = None
    latency_ms: float# api/schemas.py
from pydantic import BaseModel
from typing import List, Optional

class WAFInput(BaseModel):
    http_method: str
    request_path: str
    query_string: str
    body_snippet: str
    anomaly_tokens: List[str]
    pll_score: float
    threshold: float

class QueryRequest(BaseModel):
    type: str
    query: Optional[str] = None
    waf_data: Optional[WAFInput] = None

class QueryResponse(BaseModel):
    answer: str
    cve_references: Optional[str] = None
    cwe_references: Optional[str] = None
    owasp_references: Optional[str] = None
    confidence: Optional[str] = None
    context_gap: Optional[str] = None
    latency_ms: float