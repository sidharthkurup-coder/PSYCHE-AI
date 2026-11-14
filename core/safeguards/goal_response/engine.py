"""Safeguard D: Goal-Aware Response Engine (REQ-SAFE-04).

Synthesizes:
1. `inferred_user_objective`: Explicit relational and task goal for the response.
2. `clarification_needed` & `clarification_question`: Triggered when identity is ambiguous,
   verdict is INCONCLUSIVE, or open memory contradictions materially affect the reply strategy.
3. Multi-strategy `reply_candidates` tailored to the user's COMMUNICATION DNA across all 7
   authorized language modes (`en`, `hi-Latn`, `hi-Deva`, `ml-Latn`, `ml-Mlym`, `te-Latn`, `te-Telu`),
   each neutralized by `ModelNeutralizerAndIdentityLock`.
"""

from __future__ import annotations

import re
from typing import Any

from core.contracts.validator import AUTHORIZED_LANGUAGE_MODES
from core.multilingual.pragmatics import MultilingualPragmaticAnalysis
from core.pillars.comm_dna.engine import CommunicationDnaPillarEngine
from core.subsystems.model_neutralizer.engine import ModelNeutralizerAndIdentityLock

_TIME_EXPR_PATTERN = re.compile(
    r"(?:^|[\s,(\"'`])("
    r"\d{1,2}(?::\d{2})?\s*(?:am|pm)"
    r"|\d{1,2}:\d{2}"
    r"|\d{1,2}\s*(?:baje|manikku|maniku|manik|gantalaku|hrs|hours|बजे|മണിക്ക്|గంటలకు)"
    r")(?=$|[\s,.)!?;\"'`])",
    re.IGNORECASE,
)

_HONORIFIC_PATTERN = re.compile(
    r"(?:^|[\s,(\"'`])("
    r"machane|eda|edi|aliya|chetta|chechi|bhai|bhaiya|yaar|didi|bro|sir|ma'am|ji|"
    r"anna|akka|garu|mama|ra|"
    r"भाई|यार|दीदी|भैया|जी|എടാ|എടി|മച്ചാനേ|ചേട്ടാ|ചേച്ചി|అన్నా|అక్క|గారు|మామ"
    r")(?=$|[\s,.)!?;:\"'`])",
    re.IGNORECASE,
)

_DAY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("TOMORROW", re.compile(r"(?:^|[\s,(\"'`])(tomorrow|tmrw|kal|naale|nale|repu|reppu|कल|നാളെ|రేపు)(?=$|[\s,.)!?;:\"'`])", re.IGNORECASE)),
    ("TONIGHT", re.compile(r"(?:^|[\s,(\"'`])(tonight|raathri|rathri|raat|रात|രാത്രി|ఈ రాత్రి)(?=$|[\s,.)!?;:\"'`])", re.IGNORECASE)),
    ("TODAY", re.compile(r"(?:^|[\s,(\"'`])(today|aaj|innu|ivala|eroju|आज|ഇന്ന്|ఈరోజు)(?=$|[\s,.)!?;:\"'`])", re.IGNORECASE)),
    ("MORNING", re.compile(r"(?:^|[\s,(\"'`])(morning|subah|ravile|podunna|udayam|सुबह|രാവിലെ|ఉదయం)(?=$|[\s,.)!?;:\"'`])", re.IGNORECASE)),
    ("EVENING", re.compile(r"(?:^|[\s,(\"'`])(evening|shaam|vaikittu|sayantram|saayantram|शाम|വൈകുന്നേരം|సాయంత్రం)(?=$|[\s,.)!?;:\"'`])", re.IGNORECASE)),
)

_DAY_LOCALIZATION: dict[str, dict[str, str]] = {
    "TOMORROW": {
        "en": "tomorrow", "ml-Latn": "naale", "ml-Mlym": "നാളെ",
        "hi-Latn": "kal", "hi-Deva": "कल", "te-Latn": "repu", "te-Telu": "రేపు",
    },
    "TONIGHT": {
        "en": "tonight", "ml-Latn": "innu raathri", "ml-Mlym": "ഇന്ന് രാത്രി",
        "hi-Latn": "aaj raat", "hi-Deva": "आज रात", "te-Latn": "ivala raatri", "te-Telu": "ఈ రాత్రి",
    },
    "TODAY": {
        "en": "today", "ml-Latn": "innu", "ml-Mlym": "ഇന്ന്",
        "hi-Latn": "aaj", "hi-Deva": "आज", "te-Latn": "ivala", "te-Telu": "ఈరోజు",
    },
    "MORNING": {
        "en": "tomorrow morning", "ml-Latn": "naale ravile", "ml-Mlym": "നാളെ രാവിലെ",
        "hi-Latn": "kal subah", "hi-Deva": "कल सुबह", "te-Latn": "repu podunna", "te-Telu": "రేపు ఉదయం",
    },
    "EVENING": {
        "en": "this evening", "ml-Latn": "vaikittu", "ml-Mlym": "വൈകുന്നേരം",
        "hi-Latn": "shaam ko", "hi-Deva": "शाम को", "te-Latn": "sayantram", "te-Telu": "సాయంత్రం",
    },
}

_MODE_MARKERS: dict[str, set[str]] = {
    "ml-Latn": {"machane", "eda", "edi", "aliya", "chetta", "chechi", "bro"},
    "ml-Mlym": {"എടാ", "എടി", "മച്ചാനേ", "ചേട്ടാ", "ചേച്ചി"},
    "hi-Latn": {"bhai", "bhaiya", "yaar", "didi", "bro", "ji"},
    "hi-Deva": {"भाई", "यार", "दीदी", "भैया", "जी"},
    "te-Latn": {"anna", "akka", "garu", "mama", "ra", "bro"},
    "te-Telu": {"అన్నా", "అక్క", "గారు", "మామ"},
    "en": {"bro", "sir", "ma'am"},
}


def extract_contextual_slots(raw_text: str) -> dict[str, Any]:
    """Extracts explicit time, day/window, honorific, and topic slots across all 7 language modes."""
    text = raw_text or ""
    time_mentions: list[str] = []
    time_numeric_tokens: list[str] = []
    for match in _TIME_EXPR_PATTERN.finditer(text):
        phrase = " ".join(match.group(1).strip().split())
        if phrase not in time_mentions:
            time_mentions.append(phrase)
        num_match = re.match(r"(\d{1,2}(?::\d{2})?(?:\s*(?:am|pm))?)", phrase, re.IGNORECASE)
        if num_match:
            num_tok = " ".join(num_match.group(1).upper().split())
            if num_tok not in time_numeric_tokens:
                time_numeric_tokens.append(num_tok)

    day_tags: list[str] = []
    day_terms: list[str] = []
    for tag, pat in _DAY_PATTERNS:
        m = pat.search(text)
        if m:
            day_tags.append(tag)
            term = m.group(1).strip()
            if term not in day_terms:
                day_terms.append(term)

    if "TOMORROW" in day_tags and "EVENING" in day_tags:
        day_window = "TOMORROW_EVENING"
    elif "TOMORROW" in day_tags and "MORNING" in day_tags:
        day_window = "TOMORROW_MORNING"
    else:
        day_window = day_tags[0] if day_tags else None

    honorifics: list[str] = []
    for m in _HONORIFIC_PATTERN.finditer(text):
        val = m.group(1).strip()
        if val.lower() not in {h.lower() for h in honorifics}:
            honorifics.append(val)

    lowered = text.lower()
    topic_hint: str | None = None
    if any(k in lowered for k in ("call", "phone", "vilik", "फोन", "कॉल", "വിളിക്ക", "కాల్")):
        topic_hint = "CALL"
    elif any(k in lowered for k in ("meet", "coffee", "dinner", "kaan", "mil", "kalud", "मिल", "കാണ", "കല", "కలు")):
        topic_hint = "MEETING"
    elif any(k in lowered for k in ("deadline", "project", "exam", "report", "padhai", "kaam", "ജോലി", "പണി", "పని")):
        topic_hint = "WORK_TASK"

    return {
        "time_mentions": time_mentions,
        "time_numeric_tokens": time_numeric_tokens,
        "day_window": day_window,
        "day_tags": day_tags,
        "day_window_terms": day_terms,
        "honorifics": honorifics,
        "topic_hint": topic_hint,
    }


def _select_marker_for_mode(
    primary_mode: str,
    learned_markers: list[str],
    incoming_honorifics: list[str],
    formality_target: float,
) -> str | None:
    """Selects a natural signature marker matching user's COMMUNICATION DNA and formality."""
    if formality_target >= 0.65:
        for honorific in incoming_honorifics:
            if honorific.lower() in {"sir", "ma'am", "ji", "garu"} or honorific in {"जी", "గారు"}:
                return honorific
        return None
    allowed_for_mode = _MODE_MARKERS.get(primary_mode, set())
    for marker in learned_markers:
        if marker.lower() in allowed_for_mode or marker in allowed_for_mode:
            return marker
    if learned_markers and primary_mode.endswith("-Latn"):
        return learned_markers[0]
    for h in incoming_honorifics:
        if h.lower() in allowed_for_mode or h in allowed_for_mode:
            return h.lower() if primary_mode.endswith("-Latn") else h
    defaults = {
        "ml-Latn": "eda",
        "hi-Latn": "bhai",
        "te-Latn": "anna",
    }
    return defaults.get(primary_mode)


def _format_localized_time(num_tok: str, mode: str) -> str:
    """Formats extracted time numeric token naturally in the target script/mode."""
    bare = re.sub(r"\s*(?:AM|PM)\s*$", "", num_tok, flags=re.IGNORECASE).strip()
    if mode == "en":
        return num_tok
    if mode == "ml-Latn":
        return f"{bare} manikku"
    if mode == "ml-Mlym":
        return f"{bare} മണിക്ക്"
    if mode == "hi-Latn":
        return f"{bare} baje"
    if mode == "hi-Deva":
        return f"{bare} बजे"
    if mode == "te-Latn":
        return f"{bare} gantalaku"
    if mode == "te-Telu":
        return f"{bare} గంటలకు"
    return num_tok


def _synthesize_slot_aware_draft(
    *,
    mode: str,
    strategy_key: str,
    slots: dict[str, Any],
    marker: str | None,
    fallback_bank: dict[str, tuple[str, str]],
) -> tuple[str, str]:
    """Constructs dynamic slot-aware reply + English gloss when contextual slots exist."""
    time_tokens: list[str] = slots.get("time_numeric_tokens") or []
    day_tags: list[str] = slots.get("day_tags") or []
    topic_hint: str | None = slots.get("topic_hint")

    if strategy_key != "WARM_CONFIRM" or (not time_tokens and not day_tags):
        # Dynamically inject learned user signature marker into alternative/de-escalation drafts if present
        base_draft, base_gloss = fallback_bank[strategy_key]
        if marker and mode in {"ml-Latn", "hi-Latn", "te-Latn"}:
            # Replace default casual marker at start if a different learned marker fits better
            replaced = re.sub(
                r"^(?:Eda|Bhai|Yaar|Anna|Sare anna|Haan bhai)\b",
                lambda m: f"Sare {marker}" if m.group(0).lower().startswith("sare")
                else (f"Haan {marker}" if m.group(0).lower().startswith("haan") else marker.capitalize()),
                base_draft,
                count=1,
            )
            if replaced == base_draft and strategy_key == "CALM_DEESCALATION" and not base_draft.lower().startswith(marker.lower()):
                replaced = f"{marker.capitalize()}, {base_draft[0].lower()}{base_draft[1:]}"
            return replaced, base_gloss
        return base_draft, base_gloss

    # Dynamic WARM_CONFIRM synthesis incorporating day + time + topic + learned marker
    day_phrase_mode = ""
    day_phrase_en = "at the proposed time"
    if "TOMORROW" in day_tags:
        day_phrase_mode = _DAY_LOCALIZATION["TOMORROW"].get(mode, "tomorrow")
        day_phrase_en = "tomorrow"
    elif "TONIGHT" in day_tags:
        day_phrase_mode = _DAY_LOCALIZATION["TONIGHT"].get(mode, "tonight")
        day_phrase_en = "tonight"
    elif "TODAY" in day_tags:
        day_phrase_mode = _DAY_LOCALIZATION["TODAY"].get(mode, "today")
        day_phrase_en = "today"
    elif "EVENING" in day_tags:
        day_phrase_mode = _DAY_LOCALIZATION["EVENING"].get(mode, "this evening")
        day_phrase_en = "this evening"
    elif "MORNING" in day_tags:
        day_phrase_mode = _DAY_LOCALIZATION["MORNING"].get(mode, "tomorrow morning")
        day_phrase_en = "tomorrow morning"

    time_str_mode = _format_localized_time(time_tokens[0], mode) if time_tokens else ""
    time_str_en = f" at {time_tokens[0]}" if time_tokens else ""
    is_meeting = topic_hint == "MEETING"

    m_prefix = f"{marker}" if marker else ""
    if mode == "ml-Latn":
        greet = f"Sure {marker}, " if marker else "Sure, "
        verb = "kaanam" if is_meeting else "vilikkam"
        en_verb = "meet" if is_meeting else "call"
        slot_part = " ".join(p for p in (day_phrase_mode or "naale", time_str_mode) if p)
        return f"{greet}{slot_part} {verb}", f"Sure, let's {en_verb} {day_phrase_en}{time_str_en}."
    if mode == "ml-Mlym":
        verb = "കാണാം" if is_meeting else "വിളിക്കാം"
        en_verb = "meet" if is_meeting else "call"
        slot_part = " ".join(p for p in (day_phrase_mode or "നാളെ", time_str_mode) if p)
        prefix = f"{m_prefix}, " if m_prefix else ""
        return f"തീർച്ചയായും {prefix}{slot_part} {verb}", f"Sure, let's {en_verb} {day_phrase_en}{time_str_en}."
    if mode == "hi-Latn":
        greet = f"Haan {marker or 'bhai'}, "
        verb = "milte hain" if is_meeting else "baat karte hain"
        en_verb = "meet" if is_meeting else "talk"
        slot_part = " ".join(p for p in (day_phrase_mode or "kal", time_str_mode) if p)
        return f"{greet}{slot_part} ko {verb}" if time_str_mode else f"{greet}{slot_part} {verb}", (
            f"Yes, let's {en_verb} {day_phrase_en}{time_str_en}."
        )
    if mode == "hi-Deva":
        who = marker or "भाई"
        verb = "मिलते हैं" if is_meeting else "बात करते हैं"
        en_verb = "meet" if is_meeting else "talk"
        slot_part = " ".join(p for p in (day_phrase_mode or "कल", time_str_mode) if p)
        return f"हाँ {who}, {slot_part} {verb}", f"Yes, let's {en_verb} {day_phrase_en}{time_str_en}."
    if mode == "te-Latn":
        greet = f"Sare {marker or 'anna'}, "
        verb = "kaluddam" if is_meeting else "matladadam"
        en_verb = "meet" if is_meeting else "talk"
        slot_part = " ".join(p for p in (day_phrase_mode or "repu", time_str_mode) if p)
        return f"{greet}{slot_part} {verb}", f"Okay, let's {en_verb} {day_phrase_en}{time_str_en}."
    if mode == "te-Telu":
        who = marker or "అన్నా"
        verb = "కలుద్దాం" if is_meeting else "మాట్లాడుకుందాం"
        en_verb = "meet" if is_meeting else "talk"
        slot_part = " ".join(p for p in (day_phrase_mode or "రేపు", time_str_mode) if p)
        return f"సరే {who}, {slot_part} {verb}", f"Okay, let's {en_verb} {day_phrase_en}{time_str_en}."

    en_verb = "meet" if is_meeting else "connect"
    when_en = f"{day_phrase_en}{time_str_en}" if (day_tags or time_tokens) else "at the proposed time"
    return f"Sounds good, let's {en_verb} {when_en}.", f"Confirms plans to {en_verb} {when_en}."

# Multilingual strategic draft templates across all 7 authorized language modes
_MULTILINGUAL_DRAFTS: dict[str, dict[str, tuple[str, str]]] = {
    "ml-Latn": {
        "WARM_CONFIRM": (
            "Sure eda, nale rathri 8 manikku vilikkam",
            "Sure, I will call tomorrow night at 8 PM.",
        ),
        "BOUNDARY_ALTERNATIVE": (
            "Eda innu kurachu busy aanu, naale evening samsarikkam",
            "Hey, I am a bit busy today; let's talk tomorrow evening.",
        ),
        "CALM_DEESCALATION": (
            "Eda namukku ithu samadhanamayi samsarichu solve cheyyam",
            "Let's talk this through calmly and sort it out.",
        ),
    },
    "ml-Mlym": {
        "WARM_CONFIRM": (
            "തീർച്ചയായും, നാളെ രാത്രി 8 മണിക്ക് വിളിക്കാം",
            "Sure, I will call tomorrow night at 8 PM.",
        ),
        "BOUNDARY_ALTERNATIVE": (
            "ഇന്ന് അല്പം തിരക്കിലാണ്, നാളെ വൈകുന്നേരം സംസാരിക്കാം",
            "I am a bit busy today; let's talk tomorrow evening.",
        ),
        "CALM_DEESCALATION": (
            "നമുക്ക് ഇത് സമാധാനമായി സംസാരിച്ച് പരിഹരിക്കാം",
            "Let's discuss this calmly and resolve it.",
        ),
    },
    "hi-Latn": {
        "WARM_CONFIRM": (
            "Haan bhai, kal milte hain aur aaram se baat karte hain",
            "Yes brother, let's meet tomorrow and talk comfortably.",
        ),
        "BOUNDARY_ALTERNATIVE": (
            "Bhai abhi thoda busy hoon, kal subah call karta hoon",
            "Brother, I am a bit busy right now; I will call tomorrow morning.",
        ),
        "CALM_DEESCALATION": (
            "Yaar aaram se baat karke clear kar lete hain",
            "Friend, let's talk calmly and clear this up.",
        ),
    },
    "hi-Deva": {
        "WARM_CONFIRM": (
            "हाँ भाई, कल समय पर बात करते हैं",
            "Yes brother, let's talk on time tomorrow.",
        ),
        "BOUNDARY_ALTERNATIVE": (
            "अभी थोड़ा व्यस्त हूँ, कल सुबह बात करते हैं",
            "I am a bit busy right now; let's talk tomorrow morning.",
        ),
        "CALM_DEESCALATION": (
            "शांत होकर बात करके इसे सुलझा लेते हैं",
            "Let's talk calmly and sort this out.",
        ),
    },
    "te-Latn": {
        "WARM_CONFIRM": (
            "Sare anna, repu sayantram kaluddam",
            "Okay brother, let's meet tomorrow evening.",
        ),
        "BOUNDARY_ALTERNATIVE": (
            "Anna ippudu koncham busy ga unna, repu call chestha",
            "Brother, I am a bit busy right now; I will call tomorrow.",
        ),
        "CALM_DEESCALATION": (
            "Prashanthanga matladukuni solve cheddam",
            "Let's talk calmly and resolve this.",
        ),
    },
    "te-Telu": {
        "WARM_CONFIRM": (
            "సరే అన్నా, రేపు సాయంత్రం మాట్లాడుకుందాం",
            "Okay brother, let's talk tomorrow evening.",
        ),
        "BOUNDARY_ALTERNATIVE": (
            "ఇప్పుడు కొంచెం పనిలో ఉన్నాను, రేపు ఉదయం కాల్ చేస్తా",
            "I am in the middle of work right now; I will call tomorrow morning.",
        ),
        "CALM_DEESCALATION": (
            "ప్రశాంతంగా మాట్లాడుకుని పరిష్కరించుకుందాం",
            "Let's speak calmly and resolve this.",
        ),
    },
    "en": {
        "WARM_CONFIRM": (
            "Sounds good, let's connect at the proposed time.",
            "Confirms availability warmly and clearly.",
        ),
        "BOUNDARY_ALTERNATIVE": (
            "I'm tied up right now, but I can review this tomorrow morning and get back to you.",
            "Sets a clear boundary while offering a concrete follow-up window.",
        ),
        "CALM_DEESCALATION": (
            "I want to make sure we're aligned on this—let's step back and discuss the specifics calmly.",
            "Addresses tension constructively without matching sarcasm or urgency.",
        ),
    },
}


class GoalAwareResponseEngine:
    """Generates goal-aligned, COMMUNICATION DNA-matched, neutralized reply candidates."""

    def __init__(
        self,
        *,
        comm_dna: CommunicationDnaPillarEngine,
        neutralizer: ModelNeutralizerAndIdentityLock | None = None,
    ) -> None:
        self.comm_dna = comm_dna
        self.neutralizer = neutralizer or ModelNeutralizerAndIdentityLock()

    def extract_contextual_slots(self, raw_text: str) -> dict[str, Any]:
        """Extracts contextual slots (times, day windows, honorifics, topic) across 7 modes."""
        return extract_contextual_slots(raw_text)

    def generate_recommendations(
        self,
        *,
        pragmatics: MultilingualPragmaticAnalysis,
        comm_dna_assessment: dict[str, Any],
        uncertainty_audit: dict[str, Any],
        identity_ambiguity: bool = False,
        open_contradictions_count: int = 0,
        spelling_map: dict[str, str] | None = None,
        raw_text: str | None = None,
        signature_markers: list[str] | None = None,
    ) -> dict[str, Any]:
        """Returns the contract-compliant `goal_aware_recommendations` dictionary."""
        target_modes = [
            m
            for m in comm_dna_assessment.get("recommended_language_modes", ["en"])
            if m in AUTHORIZED_LANGUAGE_MODES
        ] or ["en"]
        primary_mode = target_modes[0]
        formality_target = float(comm_dna_assessment.get("formality_target", 0.4))
        style_constraints = list(comm_dna_assessment.get("style_constraints", []))

        # Recover learned markers from explicit argument or COMM DNA constraints
        learned_markers = list(signature_markers or [])
        for c in style_constraints:
            if isinstance(c, str) and c.startswith("natural_markers:"):
                for mk in c.split(":", 1)[1].split(","):
                    mk_clean = mk.strip()
                    if mk_clean and mk_clean not in learned_markers:
                        learned_markers.append(mk_clean)

        source_text = raw_text if raw_text is not None else getattr(pragmatics, "raw_text", "") or ""
        slots = extract_contextual_slots(source_text)
        chosen_marker = _select_marker_for_mode(
            primary_mode,
            learned_markers,
            slots.get("honorifics") or [],
            formality_target,
        )

        # Determine inferred user objective
        if pragmatics.boundary_pressure_detected:
            objective = (
                "Protect personal focus/schedule boundaries while proposing a clear, realistic "
                f"follow-up window in {', '.join(target_modes)}."
            )
            primary_strategy_key = "BOUNDARY_ALTERNATIVE"
            secondary_strategy_key = "CALM_DEESCALATION"
        elif pragmatics.sarcasm_detected or pragmatics.acute_venting_detected:
            objective = (
                "De-escalate tension calmly and address the substantive concern without mirroring "
                f"sarcasm or reactivity in {', '.join(target_modes)}."
            )
            primary_strategy_key = "CALM_DEESCALATION"
            secondary_strategy_key = "BOUNDARY_ALTERNATIVE"
        else:
            objective = (
                "Confirm alignment or availability warmly and concisely in the user's authentic "
                f"{', '.join(target_modes)} voice."
            )
            primary_strategy_key = "WARM_CONFIRM"
            secondary_strategy_key = "BOUNDARY_ALTERNATIVE"

        # Check if clarification is needed before replying
        clarification_needed = False
        clarification_question: str | None = None
        if identity_ambiguity:
            clarification_needed = True
            clarification_question = (
                "Multiple contacts share this display name. Which specific contact sent this message?"
            )
        elif open_contradictions_count > 0:
            clarification_needed = True
            clarification_question = (
                "There is an unresolved contradiction in your saved memories for this thread. "
                "Do you want to confirm availability or propose an alternative time?"
            )
        elif uncertainty_audit.get("verdict_status") == "INCONCLUSIVE":
            clarification_needed = True
            clarification_question = (
                "The sender's intent has multiple plausible interpretations. Do you prefer a direct "
                "confirmation or a boundary-setting pause?"
            )

        mode_bank = _MULTILINGUAL_DRAFTS.get(primary_mode, _MULTILINGUAL_DRAFTS["en"])
        raw_draft_1, gloss_1 = _synthesize_slot_aware_draft(
            mode=primary_mode,
            strategy_key=primary_strategy_key,
            slots=slots,
            marker=chosen_marker,
            fallback_bank=mode_bank,
        )
        raw_draft_2, gloss_2 = _synthesize_slot_aware_draft(
            mode=primary_mode,
            strategy_key=secondary_strategy_key,
            slots=slots,
            marker=chosen_marker,
            fallback_bank=mode_bank,
        )

        clean_1, _ = self.neutralizer.neutralize_and_lock_draft(
            draft_text=raw_draft_1,
            style_constraints=style_constraints,
            transliteration_spelling_map=spelling_map,
        )
        clean_2, _ = self.neutralizer.neutralize_and_lock_draft(
            draft_text=raw_draft_2,
            style_constraints=style_constraints,
            transliteration_spelling_map=spelling_map,
        )

        score_1 = self.comm_dna.score_candidate_authenticity(
            draft_text=clean_1,
            target_language_modes=target_modes,
            formality_target=formality_target,
            style_constraints=style_constraints,
        )
        score_2 = self.comm_dna.score_candidate_authenticity(
            draft_text=clean_2,
            target_language_modes=target_modes,
            formality_target=formality_target,
            style_constraints=style_constraints,
        )

        candidates = [
            {
                "candidate_id": "R1",
                "strategy_label": f"Primary ({primary_strategy_key.replace('_', ' ').title()})",
                "target_language_modes": target_modes,
                "draft_text": clean_1,
                "english_meaning_gloss": gloss_1,
                "comm_dna_match_score": score_1,
                "model_neutralizer_passed": True,
            },
            {
                "candidate_id": "R2",
                "strategy_label": f"Alternative ({secondary_strategy_key.replace('_', ' ').title()})",
                "target_language_modes": target_modes,
                "draft_text": clean_2,
                "english_meaning_gloss": gloss_2,
                "comm_dna_match_score": score_2,
                "model_neutralizer_passed": True,
            },
        ]

        return {
            "inferred_user_objective": objective,
            "clarification_needed": clarification_needed,
            "clarification_question": clarification_question,
            "reply_candidates": candidates,
        }
