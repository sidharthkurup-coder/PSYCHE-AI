"""Seven-Mode Multilingual Pragmatics Engine (REQ-LANG-01 through REQ-LANG-05).

Supports strictly the 7 authorized PSYCHE AI language modes:
- en (English)
- hi-Latn (Hindi in English letters / Hinglish)
- hi-Deva (Hindi in Devanagari script)
- ml-Latn (Malayalam in English letters / Manglish)
- ml-Mlym (Malayalam in Malayalam script)
- te-Latn (Telugu in English letters / Telugish)
- te-Telu (Telugu in Telugu script)

Preserves original messages verbatim while extracting:
1. Code-mix ratios and dominant script/language modes.
2. Pronoun & honorific intimacy/formality tiers (nee/ningal, tu/tum/aap, nuvvu/meeru, chechi/chettan, garu, ji).
3. Colloquial idioms and cultural expressions with English meaning glosses.
4. Sarcasm, irony, and passive-aggressive subtext across all 7 modes.
5. Speech-act classification and emotional arousal/valence cues.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from core.contracts.validator import (
    AUTHORIZED_LANGUAGE_MODES,
    detect_language_modes_and_spans,
    normalize_phonetic_search_key,
)


@dataclass(frozen=True)
class MultilingualPragmaticAnalysis:
    """Immutable result of 7-mode multilingual pragmatic analysis."""

    raw_text_verbatim: str
    detected_language_modes: list[str]
    code_mix_ratio: dict[str, float]
    is_code_mixed: bool
    has_out_of_scope_script: bool
    speech_acts: list[str]
    formality_estimate: float
    intimacy_markers: list[str]
    respect_honorifics: list[str]
    sarcasm_detected: bool
    idiom_detected: bool
    idiom_or_colloquial_notes: str | None
    literal_meaning: str
    pragmatic_subtext: str
    emotional_valence: float
    emotional_arousal: float
    acute_venting_detected: bool
    boundary_pressure_detected: bool


# Cultural idioms & colloquialisms across the 7 authorized modes -> (mode, idiom_label, meaning_gloss)
_MULTILINGUAL_IDIOM_LEXICON: tuple[tuple[re.Pattern[str], str, str, str], ...] = (
    # Manglish / Malayalam (ml-Latn, ml-Mlym)
    (
        re.compile(r"\bscene\s+contra\b|സീൻ\s*കോൺട്ര", re.IGNORECASE),
        "ml-Latn/ml-Mlym",
        "scene contra / സീൻ കോൺട്ര",
        "Situation has escalated or turned problematic/hostile.",
    ),
    (
        re.compile(r"\b(?:adipoli|pwoli|poli\s+sadhanam)\b|അടിപൊളി|പൊളി", re.IGNORECASE),
        "ml-Latn/ml-Mlym",
        "adipoli / pwoli (അടിപൊളി)",
        "Awesome, excellent, or enthusiastic approval.",
    ),
    (
        re.compile(r"\btheppu\b|തേപ്പ്", re.IGNORECASE),
        "ml-Latn/ml-Mlym",
        "theppu (തേപ്പ്)",
        "Broken promise, betrayal, or being stood up at the last moment.",
    ),
    (
        re.compile(r"\bonnum\s+parayanda\b|ഒന്നും\s+പറയണ്ട", re.IGNORECASE),
        "ml-Latn/ml-Mlym",
        "onnum parayanda (ഒന്നും പറയണ്ട)",
        "Don't even get me started / expressing exasperation.",
    ),
    (
        re.compile(r"\bini\s+mindilla\b|ഇനി\s+മിണ്ടില്ല", re.IGNORECASE),
        "ml-Latn/ml-Mlym",
        "ini mindilla (ഇനി മിണ്ടില്ല)",
        "Expressing acute frustration or refusing to speak further.",
    ),
    # Hinglish / Hindi (hi-Latn, hi-Deva)
    (
        re.compile(r"\bbatti\s+gul\b|बत्ती\s+गुल", re.IGNORECASE),
        "hi-Latn/hi-Deva",
        "batti gul (बत्ती गुल)",
        "Power/mind went blank or complete exhaustion/shutdown.",
    ),
    (
        re.compile(r"\bkya\s+scene\s+hai\b|क्या\s+सीन\s+है", re.IGNORECASE),
        "hi-Latn/hi-Deva",
        "kya scene hai (क्या सीन है)",
        "Asking for the current plan, status update, or arrangement.",
    ),
    (
        re.compile(r"\bmazaak\s+uda\b|\bmazaak\s+kar\b|मज़ाक\s+कर", re.IGNORECASE),
        "hi-Latn/hi-Deva",
        "mazaak kar raha (मज़ाक कर रहा)",
        "Joking around or teasing lightly.",
    ),
    (
        re.compile(r"\bbhua\s+mat\s+bano\b|\bbhav\s+kha\b|भाव\s+खा", re.IGNORECASE),
        "hi-Latn/hi-Deva",
        "bhav khana (भाव खाना)",
        "Acting aloof, hard to get, or overly important.",
    ),
    # Telugish / Telugu (te-Latn, te-Telu)
    (
        re.compile(r"\b(?:light\s+teesko|lite\s+teesko)\b|లైట్\s+తీసుకో", re.IGNORECASE),
        "te-Latn/te-Telu",
        "light teesko (లైట్ తీసుకో)",
        "Take it easy, relax, or let it go without overthinking.",
    ),
    (
        re.compile(r"\bbisket\b|\bbiscuit\s+vesav\b|బిస్కెట్", re.IGNORECASE),
        "te-Latn/te-Telu",
        "bisket (బిస్కెట్)",
        "Flattering, exaggerating, or telling a tall tale.",
    ),
    (
        re.compile(r"\bchala\s+bagundi\b|చాలా\s+బాగుంది", re.IGNORECASE),
        "te-Latn/te-Telu",
        "chala bagundi (చాలా బాగుంది)",
        "Very good / warm appreciation.",
    ),
    (
        re.compile(r"\bem\s+chestam\b|ఏం\s+చేస్తాం", re.IGNORECASE),
        "te-Latn/te-Telu",
        "em chestam (ఏం చేస్తాం)",
        "What can we do? (resigned acceptance of a situation).",
    ),
    # English idioms
    (
        re.compile(r"\b(?:under\s+the\s+bus|burn\s+the\s+midnight\s+oil|on\s+the\s+same\s+page|last\s+straw)\b", re.IGNORECASE),
        "en",
        "English idiomatic expression",
        "Figurative workplace/interpersonal idiom signaling alignment, overwork, or boundary limit.",
    ),
)

# Sarcasm & passive-aggressive patterns across all 7 modes
_SARCASM_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"\b(?:oh\s+great|yeah\s+right|how\s+wonderful|thanks\s+a\s+lot\s+for\s+nothing|so\s+helpful\s+of\s+you)\b",
            re.IGNORECASE,
        ),
        "English ironic praise paired with frustration or complaint.",
    ),
    (
        re.compile(
            r"\bvalare\s+nannayi\b.*?\b(?:ippo|ippozhaano|late)\b|വളരെ\s+നന്നായി.*?ഇപ്പോഴാണോ",
            re.IGNORECASE,
        ),
        "Malayalam/Manglish sarcastic praise ('valare nannayi' / 'വളരെ നന്നായി') criticizing a delayed update.",
    ),
    (
        re.compile(
            r"\bbahut\s+(?:badhiya|achha|khoob)\b.*?\b(?:ab\s+bata|late|bhool)\b|बहुत\s+बढ़िया.*?अब\s+बता",
            re.IGNORECASE,
        ),
        "Hindi/Hinglish sarcastic praise ('bahut badhiya' / 'बहुत बढ़िया') pointing out tardiness or neglect.",
    ),
    (
        re.compile(
            r"\bchala\s+goppaga\b|చాలా\s+గొప్పగా\s+చెప్పావ్",
            re.IGNORECASE,
        ),
        "Telugu/Telugish sarcastic remark ('chala goppaga' / 'చాలా గొప్పగా') signaling skepticism or irritation.",
    ),
    (
        re.compile(
            r"^(?:fine\.|whatever\.|sheri\s+enna\.?|ശരി\s+എന്നാ\.?|rehne\s+do\.?|रहने\s+दो\.?|sare\s+le\.?|సరే\s+లే\.?)$",
            re.IGNORECASE,
        ),
        "Curt, passive-aggressive closure signaling unresolved displeasure.",
    ),
)

_INTIMATE_MARKERS = re.compile(
    r"\b(?:eda|edi|machane|aliya|nee|tu|yaar|bhai|bro|nuvvu|ra|mama|machi)\b|"
    r"(?:എടാ|എടി|മച്ചാനെ|നീ|तू|यार|भाई|నువ్వు|రా|మామ)",
    re.IGNORECASE,
)

_RESPECT_HONORIFICS = re.compile(
    r"\b(?:ningal|chechi|chettan|chetta|aap|ji|bhaiya|didi|meeru|andi|garu|gaaru|anna|akka|sir|madam)\b|"
    r"(?:നിങ്ങൾ|ചേച്ചി|ചേട്ടൻ|आप|जी|भैया|दीदी|మీరు|అండి|గారు|అన్నా|అక్క)",
    re.IGNORECASE,
)

_BOUNDARY_PRESSURE_PATTERNS = re.compile(
    r"\b(?:urgent|asap|right\s+now|immediately|tonight\s+itself|don't\s+make\s+excuses|"
    r"ippo\s+thanne|abhi\s+ke\s+abhi|ippude\s+chey|no\s+excuses)\b|"
    r"(?:ഇപ്പോൾ\s+തന്നെ|अभी\s+के\s+अभी|ఇప్పుడే)",
    re.IGNORECASE,
)

_ACUTE_VENTING_PATTERNS = re.compile(
    r"\b(?:never\s+talking|hate\s+this|completely\s+useless|so\s+furious|fed\s+up|"
    r"ini\s+mindilla|veruthu\s+poyi|dimag\s+kharab|bakwas|chiraku\s+vastundi)\b|"
    r"(?:ഇനി\s+മിണ്ടില്ല|വെറുത്തു\s+പോയി|दिमाग\s+खराब|చిరాకు)",
    re.IGNORECASE,
)

_SCHEDULING_PATTERNS = re.compile(
    r"\b(?:call|meet|meeting|tomorrow|tonight|evening|morning|time|schedule|"
    r"nale|rathri|manikku|vilikkam|vilikkamo|cheyyamo|varumo|"
    r"kal|milte|baat\s+karte|repu|intiki|vastava|kaluddam)\b|"
    r"(?:നാളെ|രാത്രി|മണിക്ക്|വിളിക്കാം|कल|मिलते|రేపు|వస్తావా)",
    re.IGNORECASE,
)


class MultilingualPragmaticsEngine:
    """Analyzes literal meaning, cultural subtext, idioms, sarcasm, and code-mixing across the 7 modes."""

    def analyze_message(self, raw_text: str) -> MultilingualPragmaticAnalysis:
        """Performs non-destructive 7-mode pragmatic analysis while preserving raw_text verbatim."""
        verbatim = str(raw_text)
        modes, spans = detect_language_modes_and_spans(verbatim)

        has_out_of_scope = "out_of_scope" in modes
        authorized_modes = [m for m in modes if m in AUTHORIZED_LANGUAGE_MODES]
        if not authorized_modes:
            authorized_modes = ["en"]

        # Compute token-level code-mix ratio across authorized modes
        mode_counts: dict[str, int] = {}
        for sp in spans:
            m = sp["language_mode"]
            if m in AUTHORIZED_LANGUAGE_MODES:
                mode_counts[m] = mode_counts.get(m, 0) + 1
        total_tokens = sum(mode_counts.values())
        if total_tokens > 0:
            code_mix_ratio = {
                m: round(cnt / total_tokens, 3) for m, cnt in mode_counts.items()
            }
        else:
            code_mix_ratio = {authorized_modes[0]: 1.0}

        is_code_mixed = len(code_mix_ratio) > 1

        # Extract intimacy markers and respect honorifics
        intimacy_found = list(dict.fromkeys(m.group(0) for m in _INTIMATE_MARKERS.finditer(verbatim)))
        honorifics_found = list(dict.fromkeys(m.group(0) for m in _RESPECT_HONORIFICS.finditer(verbatim)))

        # Estimate formality [0.0 = very casual/intimate, 1.0 = highly formal]
        formality = 0.45
        if intimacy_found:
            formality -= 0.25
        if honorifics_found:
            formality += 0.25
        if any(w in verbatim.lower() for w in ("dear ", "regards", "sincerely", "kindly", "please find")):
            formality += 0.30
        formality = round(max(0.05, min(0.95, formality)), 2)

        # Detect idioms and colloquialisms
        idiom_notes_list: list[str] = []
        for pattern, mode_tag, label, gloss in _MULTILINGUAL_IDIOM_LEXICON:
            if pattern.search(verbatim):
                idiom_notes_list.append(f"[{mode_tag}] '{label}': {gloss}")
        idiom_detected = len(idiom_notes_list) > 0

        # Detect sarcasm / passive-aggressive subtext
        sarcasm_notes: list[str] = []
        for pattern, desc in _SARCASM_PATTERNS:
            if pattern.search(verbatim.strip()):
                sarcasm_notes.append(desc)
        sarcasm_detected = len(sarcasm_notes) > 0

        combined_notes = "; ".join(idiom_notes_list + sarcasm_notes) if (idiom_notes_list or sarcasm_notes) else None

        # Detect speech acts, boundary pressure, and acute venting
        boundary_pressure = bool(_BOUNDARY_PRESSURE_PATTERNS.search(verbatim))
        acute_venting = bool(_ACUTE_VENTING_PATTERNS.search(verbatim))
        is_sched = bool(_SCHEDULING_PATTERNS.search(verbatim))
        norm_phonetic = normalize_phonetic_search_key(verbatim)
        is_question = "?" in verbatim or bool(
            re.search(
                r"\b(?:evide|eppo|varumo|cheyyamo|undo|aano|kazhinjo|ekkada|eppudu|vastava|kahan|kab|kaise|kya|can\s+you|will\s+you)\b|"
                r"(?:എവിടെ|എപ്പോൾ|വരുമോ|ചെയ്യാമോ|പറ്റുമോ|कब|कहाँ|क्या|ఎక్కడ|ఎప్పుడు|వస్తావా)",
                verbatim,
                re.IGNORECASE,
            )
            or re.search(r"\b(?:evide|eppo|varumo|cheyyamo|ekkada|eppudu|vastava|kahan|kab)\b", norm_phonetic)
        )
        is_commitment = bool(
            re.search(
                r"\b(?:i\s+will|i'll|vilikkam|varaam|cheyyam|chestha|vastha|karunga|bhejunga|milte\s+hain)\b|"
                r"(?:വിളിക്കാം|വരാം|ചെയ്യാം|भेजूंगा|मिलते हैं|చేస్తా|వస్తా)",
                verbatim,
                re.IGNORECASE,
            )
        )

        speech_acts: list[str] = []
        if is_sched:
            speech_acts.append("SCHEDULING_COORDINATION")
        if is_question:
            speech_acts.append("QUESTION_INQUIRY")
        if is_commitment:
            speech_acts.append("COMMITMENT_STATEMENT")
        if boundary_pressure:
            speech_acts.append("URGENCY_OR_BOUNDARY_PRESSURE")
        if acute_venting:
            speech_acts.append("ACUTE_EMOTIONAL_VENTING")
        if sarcasm_detected:
            speech_acts.append("SARCASTIC_OR_PASSIVE_AGGRESSIVE_REMARK")
        if not speech_acts:
            speech_acts.append("CONVERSATIONAL_STATEMENT")

        # Compute emotional valence [-1.0 to +1.0] and arousal [0.0 to 1.0]
        valence = 0.15
        arousal = 0.35
        if acute_venting or sarcasm_detected:
            valence = -0.65
            arousal = 0.85
        elif boundary_pressure:
            valence = -0.25
            arousal = 0.80
        elif any(
            w in verbatim.lower()
            for w in ("thanks", "thank you", "happy", "love", "adipoli", "pwoli", "bagundi", "badhiya", "super")
        ) or any(w in verbatim for w in ("അടിപൊളി", "చాలా బాగుంది", "बहुत बढ़िया")):
            valence = 0.75
            arousal = 0.55

        # Construct literal meaning and pragmatic subtext
        mode_summary = "+".join(authorized_modes)
        literal_meaning = f"[{mode_summary}] Verbatim message: \"{verbatim}\""
        if sarcasm_detected:
            pragmatic_subtext = (
                f"Surface phrasing diverges from intent: {'; '.join(sarcasm_notes)} "
                "Sender is signaling frustration or unresolved dissatisfaction rather than literal agreement."
            )
        elif acute_venting:
            pragmatic_subtext = (
                "High-arousal emotional discharge detected. Treat as transient frustration "
                "(Safeguard B Emotional Quarantine applies) rather than a permanent relational shift."
            )
        elif boundary_pressure:
            pragmatic_subtext = (
                "High-urgency demand or boundary pressure detected; evaluate against user's active schedule "
                "and boundary commitments before consenting."
            )
        elif is_sched and is_question:
            pragmatic_subtext = (
                "Relational coordination inquiry seeking time confirmation or availability alignment."
            )
        elif idiom_detected:
            pragmatic_subtext = f"Colloquial/cultural expression shapes subtext: {'; '.join(idiom_notes_list)}"
        else:
            pragmatic_subtext = (
                "Direct interpersonal communication consistent with surface phrasing and relationship rapport."
            )

        return MultilingualPragmaticAnalysis(
            raw_text_verbatim=verbatim,
            detected_language_modes=authorized_modes,
            code_mix_ratio=code_mix_ratio,
            is_code_mixed=is_code_mixed,
            has_out_of_scope_script=has_out_of_scope,
            speech_acts=speech_acts,
            formality_estimate=formality,
            intimacy_markers=intimacy_found,
            respect_honorifics=honorifics_found,
            sarcasm_detected=sarcasm_detected,
            idiom_detected=idiom_detected,
            idiom_or_colloquial_notes=combined_notes,
            literal_meaning=literal_meaning,
            pragmatic_subtext=pragmatic_subtext,
            emotional_valence=round(valence, 2),
            emotional_arousal=round(arousal, 2),
            acute_venting_detected=acute_venting,
            boundary_pressure_detected=boundary_pressure,
        )
