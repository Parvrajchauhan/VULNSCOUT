# VulnScout RAG – Data Sources (Short Overview)

This document explains the core data sources used in the VulnScout RAG pipeline and how they contribute to security reasoning.

---

## 1. NVD (CVE Data)

- Source: NIST National Vulnerability Database  
- Purpose: Real-world vulnerabilities  
- Updated: Daily  

**Embedded:**  
CVE ID + vulnerability description  

**Metadata:**  
CVSS score, severity, CWE ID, published date  

**Role:**  
Provides *actual attack instances* → used for detection and reference  
Section label: `cve_description`

---

## 2. OWASP Top 10

- Source: OWASP Foundation  
- Purpose: Common web attack categories  
- Updated: Every few years  

**Structure:**  
Overview, Description, Prevention, Examples  

**Embedded:**  
Category + section content  

**Role:**  
- Explains *how attacks work*  
- Provides *mitigation strategies*  

Section labels:  
- `attack_category` (concepts)  
- `mitigation_guide` (fixes)  
- `attack_example` (examples)

---

## 3. CWE (Weaknesses)

- Source: MITRE  
- Purpose: Root causes of vulnerabilities  

**Embedded:**  
CWE ID + description  

**Metadata:**  
Name, consequences, abstraction level  

**Role:**  
Explains *why vulnerabilities exist* (e.g., SQL injection root cause)  
Section label: `weakness_detail`

---

## RAG Logic

Each source serves a different purpose:

- CVE → real-world vulnerabilities  
- OWASP → attack understanding + prevention  
- CWE → underlying weakness  

A reranker boosts results based on query intent:
- "fix/prevent" → OWASP mitigation  
- "why" → CWE  
- CVE/product queries → NVD  

---

## Key Idea

Combining these sources creates a **complete security pipeline**:

- Detect → (CVE)  
- Explain → (OWASP)  
- Root Cause → (CWE)  