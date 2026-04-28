from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


TOKEN_RE = re.compile(r"[a-zA-Z0-9$%']+")


@dataclass
class ClassificationResult:
    label: str
    legit_probability: float
    spam_probability: float
    confidence: float
    tokens_checked: int
    reasons: list[str]


class NaiveBayesSpamClassifier:
    def __init__(self, training_path: Path) -> None:
        self.training_path = training_path
        self.vocabulary: set[str] = set()
        self.class_totals: Counter[str] = Counter()
        self.word_totals: dict[str, Counter[str]] = {
            "spam": Counter(),
            "legit": Counter(),
        }
        self.document_counts: Counter[str] = Counter()
        self._train()

    def _train(self) -> None:
        rows = json.loads(self.training_path.read_text(encoding="utf-8"))
        for row in rows:
            label = row["label"]
            tokens = list(self.tokenize(row["text"]))
            self.document_counts[label] += 1
            self.class_totals[label] += len(tokens)
            for token in tokens:
                self.word_totals[label][token] += 1
                self.vocabulary.add(token)

    @staticmethod
    def tokenize(text: str) -> Iterable[str]:
        lowered = text.lower()
        for token in TOKEN_RE.findall(lowered):
            if len(token) > 1:
                yield token

    def _score(self, label: str, tokens: list[str]) -> float:
        doc_total = sum(self.document_counts.values()) or 1
        prior = math.log((self.document_counts[label] + 1) / (doc_total + 2))
        vocab_size = max(len(self.vocabulary), 1)
        total_words = self.class_totals[label] + vocab_size
        score = prior
        for token in tokens:
            token_count = self.word_totals[label][token] + 1
            score += math.log(token_count / total_words)
        return score

    def classify(
        self,
        subject: str = "",
        body: str = "",
        headers_text: str = "",
        header_penalty: float = 0.0,
    ) -> ClassificationResult:
        combined = "\n".join(part for part in [subject, body, headers_text] if part.strip())
        tokens = list(self.tokenize(combined))
        if not tokens:
            return ClassificationResult(
                label="unknown",
                legit_probability=50.0,
                spam_probability=50.0,
                confidence=0.0,
                tokens_checked=0,
                reasons=["No useful text was provided for analysis."],
            )

        spam_score = self._score("spam", tokens) + header_penalty
        legit_score = self._score("legit", tokens)
        max_score = max(spam_score, legit_score)
        spam_exp = math.exp(spam_score - max_score)
        legit_exp = math.exp(legit_score - max_score)
        total = spam_exp + legit_exp
        spam_probability = (spam_exp / total) * 100
        legit_probability = (legit_exp / total) * 100
        label = "spam" if spam_probability >= legit_probability else "legit"
        confidence = abs(spam_probability - legit_probability)
        reasons = self._build_reasons(tokens, header_penalty, label)
        return ClassificationResult(
            label=label,
            legit_probability=round(legit_probability, 2),
            spam_probability=round(spam_probability, 2),
            confidence=round(confidence, 2),
            tokens_checked=len(tokens),
            reasons=reasons,
        )

    def _build_reasons(self, tokens: list[str], header_penalty: float, label: str) -> list[str]:
        suspicious_terms = {
            "urgent",
            "winner",
            "verify",
            "bitcoin",
            "prize",
            "free",
            "password",
            "click",
            "invoice",
            "bonus",
        }
        safe_terms = {
            "meeting",
            "project",
            "schedule",
            "team",
            "invoice",
            "report",
            "thanks",
            "update",
        }
        hits = sorted(set(tokens) & suspicious_terms)
        safe_hits = sorted(set(tokens) & safe_terms)
        reasons: list[str] = []
        if hits:
            reasons.append(f"Suspicious keywords found: {', '.join(hits[:6])}.")
        if safe_hits and label == "legit":
            reasons.append(f"Business-like keywords found: {', '.join(safe_hits[:6])}.")
        if header_penalty > 0:
            reasons.append("Header analysis increased spam risk.")
        if not reasons:
            reasons.append("Decision came mostly from the trained word distribution.")
        return reasons
