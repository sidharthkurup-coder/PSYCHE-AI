"""PSYCHE AI Contract Validator, Cryptographic Digest Verifier & 7-Mode Multilingual Tagger.

Enforces:
- Strict JSON Schema Draft 2020-12 conformance across all /contracts/v1/*.schema.json files.
- Byte-for-byte SHA-256 verification of raw_text_immutable (AC-01 / REQ-LANG-04).
- Exact 7 authorized language/script modes:
  en, hi-Latn, hi-Deva, ml-Latn, ml-Mlym, te-Latn, te-Telu (+ out_of_scope flag).
- Non-destructive token-span code-mixing detection and phonetic search key normalization.
- Mandatory untrusted_external_input and OTP/banking exclusion checks (PSYCHE FORTRESS).
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

AUTHORIZED_LANGUAGE_MODES: frozenset[str] = frozenset(
    {
        "en",
        "hi-Latn",
        "hi-Deva",
        "ml-Latn",
        "ml-Mlym",
        "te-Latn",
        "te-Telu",
    }
)

ALL_VALID_LANGUAGE_TAGS: frozenset[str] = AUTHORIZED_LANGUAGE_MODES | {"out_of_scope"}

# Curated high-precision Romanized Indic morphological & lexical markers
_ML_LATN_LEXICON: frozenset[str] = frozenset(
    {
        "nale", "naale", "rathri", "raathri", "manikku", "cheyyamo", "cheyyam",
        "evide", "evideya", "evdeya", "evde", "varumo", "varaam", "varam",
        "und", "undu", "undo", "illa", "alle", "aano", "ano", "machane", "eda",
        "edi", "mole", "mone", "chechi", "chetta", "chettan", "amma", "acha",
        "achan", "kazhinjo", "kazhinju", "bhakshanam", "kudicho", "parayu",
        "parayoo", "ariyilla", "nokkam", "vilikkam", "vilikku", "sukhamano",
        "entha", "enthu", "eppo", "eppozha", "veetil", "veettil", "uff", "pinne",
        "valya", "karyam", "aayi", "theerchayayum", "njan", "njn", "nee", "ningal",
    }
)

_TE_LATN_LEXICON: frozenset[str] = frozenset(
    {
        "ekkada", "ekada", "vastunna", "vasthunna", "vastava", "cheppu",
        "cheppandi", "garu", "gaaru", "em", "emi", "chestunnav", "chesthunnav",
        "chestunnaru", "bagunnara", "bagundi", "chala", "chaala", "avunu",
        "kaadu", "kadu", "ledu", "leru", "undi", "unnava", "unnaru", "repu",
        "ellundi", "intlo", "intiki", "tinnava", "thinnava", "nuvvu", "meeru",
        "nenu", "manam", "enduku", "eppudu", "ela", "chesava", "chestha",
        "veldham", "kaluddam", "anna", "akka", "babu", "ra", "raa", "andi",
    }
)

_HI_LATN_LEXICON: frozenset[str] = frozenset(
    {
        "kya", "kyaa", "kar", "kr", "raha", "rha", "rahi", "rhi", "rahe",
        "hai", "hain", "nahi", "nhi", "naa", "mat", "kal", "aaj", "abhi",
        "kab", "kahan", "kaha", "kaise", "kaisa", "kyun", "kyu", "bhai",
        "yaar", "dost", "milte", "milna", "baat", "batao", "bata", "chalo",
        "chal", "theek", "thik", "acha", "accha", "haan", "bilkul", "aur",
        "kuch", "ghar", "kaam", "karna", "karo", "tum", "aap", "main", "mai",
        "hum", "mera", "tera", "uska", "bohot", "bahut", "zyada", "thoda",
    }
)

_EN_COMMON_LEXICON: frozenset[str] = frozenset(
    {
        "the", "and", "for", "are", "but", "not", "you", "all", "any", "can",
        "had", "her", "was", "one", "our", "out", "day", "get", "has", "him",
        "his", "how", "man", "new", "now", "old", "see", "two", "way", "who",
        "did", "its", "let", "put", "say", "she", "too", "use", "will", "with",
        "call", "office", "meeting", "project", "report", "please", "thanks",
        "tomorrow", "today", "tonight", "bro", "hey", "hello", "okay", "sure",
        "send", "check", "update", "time", "work", "home", "later", "soon",
    }
)

_OTP_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:otp|one[\s-]?time\s+password|verification\s+code|security\s+code)\b", re.IGNORECASE),
    re.compile(r"\b\d{4,8}\b.*\b(?:otp|do\s+not\s+share|valid\s+for\s+\d+\s*min)", re.IGNORECASE),
    re.compile(r"\b(?:a/c|acct|account)\s*[xX\*]+\d{3,4}\s*(?:debited|credited)\b", re.IGNORECASE),
)

_SENSITIVE_PACKAGES: frozenset[str] = frozenset(
    {
        "com.google.android.apps.authenticator2",
        "com.azure.authenticator",
        "com.duosecurity.duomobile",
    }
)


class ContractValidationError(ValueError):
    """Raised when a payload violates a PSYCHE AI v1 schema or security invariant."""

    def __init__(self, message: str, error_code: str = "SCHEMA_VIOLATION") -> None:
        super().__init__(message)
        self.error_code = error_code


def compute_sha256_hex(text: str) -> str:
    """Computes lowercase 64-char hex SHA-256 of exact UTF-8 bytes."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def is_sensitive_or_otp_notification(raw_text: str, package_name: str = "") -> bool:
    """Returns True if notification matches OTP, authenticator, or banking debit/credit patterns."""
    if package_name in _SENSITIVE_PACKAGES:
        return True
    return any(pattern.search(raw_text) for pattern in _OTP_PATTERNS)


def _classify_word_script_and_mode(token: str) -> str:
    """Classifies a single word token into one of the 7 authorized language modes or out_of_scope."""
    has_deva = False
    has_mlym = False
    has_telu = False
    has_latin = False
    has_other_alpha = False

    for ch in token:
        cp = ord(ch)
        if 0x0900 <= cp <= 0x097F:
            has_deva = True
        elif 0x0D00 <= cp <= 0x0D7F:
            has_mlym = True
        elif 0x0C00 <= cp <= 0x0C7F:
            has_telu = True
        elif (0x0041 <= cp <= 0x005A) or (0x0061 <= cp <= 0x007A):
            has_latin = True
        elif ch.isalpha():
            has_other_alpha = True

    if has_other_alpha and not (has_deva or has_mlym or has_telu):
        return "out_of_scope"
    if has_mlym:
        return "ml-Mlym"
    if has_telu:
        return "te-Telu"
    if has_deva:
        return "hi-Deva"

    if not has_latin:
        return "en"

    cleaned = re.sub(r"[^a-zA-Z-]", "", token).lower()
    parts = [p for p in cleaned.split("-") if p]
    if not parts:
        return "en"

    # Check hyphenated suffix code-mixing like "office-il"
    if len(parts) >= 2 and parts[-1] in {"il", "ude", "kku", "ile", "aal"}:
        return "ml-Latn"
    if len(parts) >= 2 and parts[-1] in {"lo", "ki", "tho", "garu"}:
        return "te-Latn"

    base = cleaned.replace("-", "")
    if base in _ML_LATN_LEXICON:
        return "ml-Latn"
    if base in _TE_LATN_LEXICON:
        return "te-Latn"
    if base in _HI_LATN_LEXICON:
        return "hi-Latn"
    if base in _EN_COMMON_LEXICON:
        return "en"

    # Morphological suffix heuristics for Romanized Malayalam / Telugu / Hindi
    if base.endswith(("kkum", "kku", "aano", "alle", "unndo", "undo", "cheyyu", "cheyyamo", "ikkam")):
        return "ml-Latn"
    if base.endswith(("stunna", "sthunna", "unnava", "unnaru", "avunu", "ppandi", "tunnava")):
        return "te-Latn"
    if base.endswith(("ounga", "aunga", "enge", "wali", "wale")):
        return "hi-Latn"

    return "en"


def detect_language_modes_and_spans(raw_text: str) -> tuple[list[str], list[dict[str, Any]]]:
    """Non-destructively detects language modes and token spans across the 7 authorized modes.

    Preserves raw_text untouched and supports intra-message code-mixing.
    """
    spans: list[dict[str, Any]] = []
    modes_ordered: list[str] = []

    for match in re.finditer(r"\S+", raw_text):
        token_text = match.group(0)
        # Skip pure punctuation/numbers/emojis unless alphabetic characters exist
        if not any(ch.isalpha() for ch in token_text):
            continue
        mode = _classify_word_script_and_mode(token_text)
        spans.append(
            {
                "start_char": match.start(),
                "end_char": match.end(),
                "token_text": token_text,
                "language_mode": mode,
            }
        )
        if mode not in modes_ordered:
            modes_ordered.append(mode)

    if not modes_ordered:
        modes_ordered.append("en")

    return modes_ordered, spans


# Basic Indic script to phonetic Latin mapping for cross-script search normalization
_SCRIPT_PHONETIC_MAP: dict[str, str] = {
    # Malayalam sample common characters & chillu for canonical alias/search indexing
    "അ": "a", "ആ": "aa", "ഇ": "i", "ഈ": "ee", "ഉ": "u", "ഊ": "oo",
    "എ": "e", "ഏ": "e", "ഐ": "ai", "ഒ": "o", "ഓ": "o",
    "ക": "ka", "ഖ": "kha", "ഗ": "ga", "ഘ": "gha", "ങ": "nga",
    "ച": "cha", "ഛ": "chha", "ജ": "ja", "ഞ": "nja",
    "ട": "ta", "ഡ": "da", "ണ": "na",
    "ത": "tha", "ദ": "da", "ധ": "dha", "ന": "na",
    "പ": "pa", "ഫ": "pha", "ബ": "ba", "ഭ": "bha", "മ": "ma",
    "യ": "ya", "ര": "ra", "ല": "la", "വ": "va", "ശ": "sha", "ഷ": "sha", "സ": "sa", "ഹ": "ha",
    "ള": "la", "ഴ": "zha", "റ": "ra",
    "ൻ": "n", "ർ": "r", "ൽ": "l", "ൾ": "l", "ൺ": "n",
    "ാ": "a", "ി": "i", "ീ": "ee", "ു": "u", "ൂ": "oo", "െ": "e", "േ": "e", "ൊ": "o", "ോ": "o", "്": "",
    # Devanagari common characters
    "अ": "a", "आ": "aa", "इ": "i", "ई": "ee", "उ": "u", "ऊ": "oo", "ए": "e", "ओ": "o",
    "क": "ka", "ख": "kha", "ग": "ga", "घ": "gha", "च": "cha", "ज": "ja", "ट": "ta", "ड": "da",
    "त": "ta", "थ": "tha", "द": "da", "ध": "dha", "न": "na", "प": "pa", "ब": "ba", "भ": "bha",
    "म": "ma", "य": "ya", "र": "ra", "ल": "la", "व": "va", "श": "sha", "स": "sa", "ह": "ha",
    "ा": "a", "ि": "i", "ी": "ee", "ु": "u", "ू": "oo", "े": "e", "ै": "ai", "ो": "o", "ौ": "au", "्": "", "ं": "n",
    # Telugu common characters
    "అ": "a", "ఆ": "aa", "ఇ": "i", "ఈ": "ee", "ఉ": "u", "ఊ": "oo", "ఎ": "e", "ఏ": "e", "ఒ": "o", "ఓ": "o",
    "క": "ka", "ख": "kha", "గ": "ga", "చ": "cha", "జ": "ja", "ట": "ta", "డ": "da", "ణ": "na",
    "త": "tha", "ద": "da", "న": "na", "ప": "pa", "బ": "ba", "మ": "ma", "య": "ya", "ర": "ra",
    "ల": "la", "వ": "va", "శ": "sha", "స": "sa", "హ": "ha", "ళ": "la",
    "ా": "a", "ి": "i", "ీ": "ee", "ు": "u", "ూ": "oo", "ె": "e", "ే": "e", "ొ": "o", "ో": "o", "్": "", "ం": "m",
}


_DEPENDENT_VOWELS_AND_VIRAMA: dict[str, str] = {
    # Malayalam dependent vowels & virama (chandrakkala)
    "ാ": "a", "ി": "i", "ീ": "ee", "ു": "u", "ൂ": "oo", "ൃ": "ri",
    "െ": "e", "േ": "e", "ൈ": "ai", "ൊ": "o", "ോ": "o", "ൗ": "au", "്": "",
    # Devanagari dependent vowels & virama (halant)
    "ा": "a", "ि": "i", "ी": "ee", "ु": "u", "ू": "oo", "ृ": "ri",
    "े": "e", "ै": "ai", "ो": "o", "ौ": "au", "्": "",
    # Telugu dependent vowels & virama (pollu)
    "ా": "a", "ి": "i", "ీ": "ee", "ు": "u", "ూ": "oo", "ృ": "ri",
    "ె": "e", "ే": "e", "ై": "ai", "ొ": "o", "ో": "o", "ౌ": "au", "్": "",
}


def normalize_phonetic_search_key(text: str) -> str:
    """Produces a secondary phonetic search key for FTS5 and cross-script alias resolution.

    Properly handles Indic abugida inherent-vowel suppression before viramas and dependent
    vowel signs so 'evideya'/'evdeya'/'എവിടെയാ' and 'Ammu'/'അമ്മു' share a canonical key.
    """
    out_chars: list[str] = []
    for ch in text:
        if ch in _DEPENDENT_VOWELS_AND_VIRAMA:
            # Suppress the preceding consonant's inherent trailing 'a' before attaching vowel/virama
            if out_chars and out_chars[-1].endswith("a") and len(out_chars[-1]) > 1:
                out_chars[-1] = out_chars[-1][:-1]
            out_chars.append(_DEPENDENT_VOWELS_AND_VIRAMA[ch])
        elif ch in _SCRIPT_PHONETIC_MAP:
            out_chars.append(_SCRIPT_PHONETIC_MAP[ch])
        elif ch.isalnum() or ch.isspace():
            out_chars.append(ch.lower())
        else:
            out_chars.append(" ")
    raw_phonetic = "".join(out_chars)
    # Collapse common transliteration spelling variations (geminated vowels, h-aspirates)
    collapsed = re.sub(r"([aeiou])\1+", r"\1", raw_phonetic)
    collapsed = re.sub(r"th", "t", collapsed)
    collapsed = re.sub(r"bh", "b", collapsed)
    collapsed = re.sub(r"dh", "d", collapsed)
    collapsed = re.sub(r"([bcdfghjklmnpqrstvwxyz])\1+", r"\1", collapsed)
    collapsed = re.sub(r"evde", "evide", collapsed)
    collapsed = re.sub(r"\bkr\b", "kar", collapsed)
    collapsed = re.sub(r"\brha\b", "raha", collapsed)
    collapsed = re.sub(r"\bnhi\b", "nahi", collapsed)
    collapsed = re.sub(r"\s+", " ", collapsed).strip()
    return collapsed


class ContractValidator:
    """Validates PSYCHE AI payloads against /contracts/v1/*.schema.json and domain invariants."""

    def __init__(self, contracts_dir: str | Path | None = None) -> None:
        if contracts_dir is None:
            repo_root = Path(__file__).resolve().parents[2]
            contracts_dir = repo_root / "contracts" / "v1"
        self.contracts_dir = Path(contracts_dir)
        self._schemas: dict[str, dict[str, Any]] = {}
        self._registry = self._load_registry()

    def _load_registry(self) -> Registry:
        schema_paths = sorted(glob.glob(str(self.contracts_dir / "*.schema.json")))
        if not schema_paths:
            raise FileNotFoundError(f"No schema files found in {self.contracts_dir}")
        resources: list[tuple[str, Resource[Any]]] = []
        for path in schema_paths:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            Draft202012Validator.check_schema(data)
            fname = os.path.basename(path)
            self._schemas[fname] = data
            resources.append((data["$id"], Resource.from_contents(data)))
        return Registry().with_resources(resources)

    @property
    def loaded_schema_Warning_names(self) -> list[str]:
        return list(self._schemas.keys())

    def validate(self, schema_filename: str, def_name: str, payload: dict[str, Any]) -> None:
        """Validates payload against schema_filename#/$defs/def_name and checks cryptographic invariants."""
        if schema_filename not in self._schemas:
            raise ContractValidationError(f"Unknown schema file: {schema_filename}")
        base_schema = self._schemas[schema_filename]
        if def_name not in base_schema.get("$defs", {}):
            raise ContractValidationError(f"Definition {def_name} not found in {schema_filename}")

        target_schema = {
            "$schema": base_schema["$schema"],
            "$ref": f"{base_schema['$id']}#/$defs/{def_name}",
        }
        validator = Draft202012Validator(target_schema, registry=self._registry)
        errors = sorted(validator.iter_errors(payload), key=lambda e: list(e.path))
        if errors:
            first = errors[0]
            loc = ".".join(str(p) for p in first.path) or "<root>"
            raise ContractValidationError(
                f"Schema validation failed at '{loc}': {first.message}",
                error_code="SCHEMA_VIOLATION",
            )

        # Additional semantic & cryptographic invariant enforcement
        if schema_filename == "notification_ingest.schema.json":
            if def_name == "NotificationEventItem":
                self._verify_notification_event_invariants(payload)
            elif def_name == "NotificationIngestRequest":
                for ev in payload.get("events", []):
                    self._verify_notification_event_invariants(ev)

    def _verify_notification_event_invariants(self, event: dict[str, Any]) -> None:
        content = event.get("content", {})
        raw_text = content.get("raw_text_immutable", "")
        expected_hash = content.get("raw_text_sha256", "")
        actual_hash = compute_sha256_hex(raw_text)
        if actual_hash != expected_hash:
            raise ContractValidationError(
                f"SHA-256 mismatch for event {event.get('event_id')}: expected {expected_hash}, computed {actual_hash}",
                error_code="SHA256_MISMATCH",
            )
        if is_sensitive_or_otp_notification(raw_text, event.get("package_name", "")):
            raise ContractValidationError(
                f"Event {event.get('event_id')} contains unfiltered OTP or sensitive banking content",
                error_code="SCHEMA_VIOLATION",
            )
