from __future__ import annotations

import re
from dataclasses import dataclass


EMAIL_RE = re.compile(r"[\w\.-]+@[\w\.-]+\.\w+")


@dataclass
class HeaderReport:
    risk_score: float
    verdict: str
    findings: list[str]
    header_penalty: float


def analyze_headers(headers_text: str) -> HeaderReport:
    lowered = headers_text.lower()
    findings: list[str] = []
    risk_score = 0.0

    if not headers_text.strip():
        return HeaderReport(
            risk_score=0.0,
            verdict="unknown",
            findings=["No header content provided."],
            header_penalty=0.0,
        )

    if "spf=fail" in lowered or "received-spf: fail" in lowered:
        risk_score += 35
        findings.append("SPF check appears to fail.")
    if "dkim=fail" in lowered:
        risk_score += 30
        findings.append("DKIM validation appears to fail.")
    if "dmarc=fail" in lowered:
        risk_score += 30
        findings.append("DMARC validation appears to fail.")
    if "reply-to:" in lowered and "from:" in lowered:
        from_match = EMAIL_RE.search(_header_line(headers_text, "From"))
        reply_match = EMAIL_RE.search(_header_line(headers_text, "Reply-To"))
        if from_match and reply_match and from_match.group(0).lower() != reply_match.group(0).lower():
            risk_score += 20
            findings.append("Reply-To address does not match From address.")
    if "x-priority: 1" in lowered or "importance: high" in lowered:
        risk_score += 10
        findings.append("Message marks itself as high urgency.")
    if "return-path:" not in lowered:
        risk_score += 8
        findings.append("Return-Path header is missing.")
    if "message-id:" not in lowered:
        risk_score += 8
        findings.append("Message-ID header is missing.")
    if len(re.findall(r"received:", lowered)) <= 1:
        risk_score += 6
        findings.append("Very few Received hops were found.")

    verdict = "likely legit"
    if risk_score >= 60:
        verdict = "high risk"
    elif risk_score >= 30:
        verdict = "needs review"

    if not findings:
        findings.append("No obvious header red flags were found.")

    return HeaderReport(
        risk_score=round(risk_score, 2),
        verdict=verdict,
        findings=findings,
        header_penalty=round(risk_score / 12, 2),
    )


def _header_line(headers_text: str, name: str) -> str:
    for line in headers_text.splitlines():
        if line.lower().startswith(f"{name.lower()}:"):
            return line
    return ""
