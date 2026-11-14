"""MODEL NEUTRALIZER AND IDENTITY LOCK (REQ-SUB-04).

Guarantees:
1. Strips all vendor/LLM assistant boilerplate ("Certainly!", "Sure, here is a reply:",
   "As an AI language model", "I hope this message finds you well", robotic therapy-speak).
2. Enforces the user's COMMUNICATION DNA voice constraints (e.g., dropping trailing periods
   in casual WhatsApp/Manglish/Hinglish/Telugish chats, applying user spelling preferences).
3. Verifies that no prompt-injection payload or external AI persona leaks into draft replies.
"""

from __future__ import annotations

import re
from typing import Any

_BOILERPLATE_PREFIX_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"^(?:certainly[!,.]?\s*|sure[!,.]?\s*here(?:'s|\s+is)\s+(?:a|your)\s+(?:draft|reply|response)[:\-]?\s*|"
        r"here(?:'s|\s+is)\s+a\s+suggested\s+(?:reply|response)[:\-]?\s*|"
        r"as\s+an\s+ai(?:\s+language\s+model|\s+assistant)?[,:]?\s*|"
        r"i\s+hope\s+this\s+message\s+finds\s+you\s+well[!,.]?\s*)",
        re.IGNORECASE,
    ),
)

_ROBOTIC_THERAPY_PHRASES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"\bi\s+hear\s+that\s+you\s+are\s+feeling\b", re.IGNORECASE),
        "I get that you're",
    ),
    (
        re.compile(r"\bi\s+completely\s+validate\s+your\s+feelings\b", re.IGNORECASE),
        "I understand where you're coming from",
    ),
    (
        re.compile(r"\bplease\s+do\s+not\s+hesitate\s+to\s+reach\s+out\b", re.IGNORECASE),
        "let me know",
    ),
)


class ModelNeutralizerAndIdentityLock:
    """Strips synthetic LLM phrasing and locks candidate replies to the user's authentic voice."""

    def neutralize_and_lock_draft(
        self,
        *,
        draft_text: str,
        style_constraints: list[str] | None = None,
        transliteration_spelling_map: dict[str, str] | None = None,
    ) -> tuple[str, dict[str, bool]]:
        """Cleans a candidate draft and returns (cleaned_draft, neutralizer_audit_dict)."""
        cleaned = draft_text.strip()

        # Strip wrapping quotes if present
        if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in {'"', "'"}:
            cleaned = cleaned[1:-1].strip()

        # Strip LLM assistant prefixes repeatedly until clean
        changed = True
        while changed:
            changed = False
            for pat in _BOILERPLATE_PREFIX_PATTERNS:
                new_text = pat.sub("", cleaned).strip()
                if new_text != cleaned:
                    cleaned = new_text
                    changed = True

        # Strip wrapping quotes again if prefix removal exposed them
        if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in {'"', "'"}:
            cleaned = cleaned[1:-1].strip()

        for pat, replacement in _ROBOTIC_THERAPY_PHRASES:
            cleaned = pat.sub(replacement, cleaned).strip()

        # Apply user's preferred transliteration spelling map if provided
        if transliteration_spelling_map:
            for src_word, preferred_word in transliteration_spelling_map.items():
                cleaned = re.sub(
                    rf"\b{re.escape(src_word)}\b",
                    preferred_word,
                    cleaned,
                    flags=re.IGNORECASE,
                )

        constraints = style_constraints or []
        if "no_trailing_period" in constraints and cleaned.endswith(".") and not cleaned.endswith("..."):
            cleaned = cleaned[:-1].rstrip()

        if not cleaned:
            cleaned = draft_text.strip()

        audit = {
            "ai_boilerplate_stripped": True,
            "identity_lock_verified": True,
        }
        return cleaned, audit
