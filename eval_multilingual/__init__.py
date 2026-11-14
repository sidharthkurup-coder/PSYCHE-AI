"""Multilingual 7-mode golden evaluation suite for PSYCHE AI (AC-01, AC-03)."""

from eval_multilingual.golden_corpus import (
    GOLDEN_MULTILINGUAL_CORPUS,
    GoldenEvalCase,
    evaluate_golden_corpus,
)

__all__ = [
    "GOLDEN_MULTILINGUAL_CORPUS",
    "GoldenEvalCase",
    "evaluate_golden_corpus",
]
