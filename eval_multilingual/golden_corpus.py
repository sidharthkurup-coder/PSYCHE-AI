"""210-Case Golden Multilingual Pragmatic Evaluation Suite (30 cases x 7 authorized modes).

Covers strictly the 7 authorized PSYCHE AI language modes (`AC-03`, `REQ-LANG-01..05`):
- `en` (English)
- `hi-Latn` (Hindi in Roman script / Hinglish)
- `hi-Deva` (Hindi in Devanagari script)
- `ml-Latn` (Malayalam in Roman script / Manglish)
- `ml-Mlym` (Malayalam in Malayalam script)
- `te-Latn` (Telugu in Roman script / Telugish)
- `te-Telu` (Telugu in Telugu script)

Every case verifies:
1. `AC-01` byte-for-byte SHA-256 preservation of `raw_text_verbatim`.
2. Accurate 7-mode & intra-message code-mix detection with zero `out_of_scope` leaks.
3. Pragmatic subtext fidelity (speech acts, sarcasm, cultural idioms, emotional venting,
   boundary pressure, honorific formality estimation, and emotional valence polarity).
4. Optional contextual slot extraction (explicit clock times / day windows).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from core.contracts.validator import AUTHORIZED_LANGUAGE_MODES, compute_sha256_hex
from core.multilingual.pragmatics import MultilingualPragmaticsEngine
from core.safeguards.goal_response.engine import extract_contextual_slots


@dataclass(frozen=True)
class GoldenEvalCase:
    """Single golden benchmark case across the 7 authorized language modes."""

    case_id: str
    target_mode: str
    raw_text: str
    expected_detected_modes: tuple[str, ...]
    expected_speech_acts: tuple[str, ...] = ()
    expected_sarcasm: bool | None = None
    expected_idiom: bool | None = None
    expected_acute_venting: bool | None = None
    expected_boundary_pressure: bool | None = None
    expected_formality_range: tuple[float, float] | None = None
    expected_valence_sign: str | None = None
    expected_slot_time: bool = False


def _build_en_cases() -> list[GoldenEvalCase]:
    return [
        GoldenEvalCase("EVAL-EN-01", "en", "Hey bro, can you call me tomorrow at 8 PM?", ("en",), ("SCHEDULING_COORDINATION", "QUESTION_INQUIRY"), expected_formality_range=(0.05, 0.35), expected_slot_time=True),
        GoldenEvalCase("EVAL-EN-02", "en", "Good morning sir, please send the project update before noon.", ("en",), expected_formality_range=(0.55, 0.95)),
        GoldenEvalCase("EVAL-EN-03", "en", "Oh great, you forgot the meeting again after promising yesterday.", ("en",), ("SARCASTIC_OR_PASSIVE_AGGRESSIVE_REMARK",), expected_sarcasm=True, expected_valence_sign="negative"),
        GoldenEvalCase("EVAL-EN-04", "en", "I need the budget spreadsheet approved right now, no excuses!", ("en",), ("URGENCY_OR_BOUNDARY_PRESSURE",), expected_boundary_pressure=True, expected_valence_sign="negative"),
        GoldenEvalCase("EVAL-EN-05", "en", "We had to burn the midnight oil to ship the release.", ("en",), expected_idiom=True),
        GoldenEvalCase("EVAL-EN-06", "en", "Let's make sure we are on the same page before Monday's call.", ("en",), ("SCHEDULING_COORDINATION",), expected_idiom=True),
        GoldenEvalCase("EVAL-EN-07", "en", "That constant interruption at dinner was the last straw for me.", ("en",), expected_idiom=True),
        GoldenEvalCase("EVAL-EN-08", "en", "Please do not throw teammates under the bus during the review.", ("en",), expected_idiom=True),
        GoldenEvalCase("EVAL-EN-09", "en", "I'm so furious and completely fed up with you right now!", ("en",), ("ACUTE_EMOTIONAL_VENTING",), expected_acute_venting=True, expected_valence_sign="negative"),
        GoldenEvalCase("EVAL-EN-10", "en", "Thank you so much for your kindness and patience today.", ("en",), expected_valence_sign="positive"),
        GoldenEvalCase("EVAL-EN-11", "en", "Can we schedule our design review tomorrow at 10:30 AM?", ("en",), ("SCHEDULING_COORDINATION", "QUESTION_INQUIRY"), expected_slot_time=True),
        GoldenEvalCase("EVAL-EN-12", "en", "I will send the updated notes tonight after dinner.", ("en",), ("SCHEDULING_COORDINATION", "COMMITMENT_STATEMENT")),
        GoldenEvalCase("EVAL-EN-13", "en", "How wonderful, another surprise deadline two hours before departure.", ("en",), ("SARCASTIC_OR_PASSIVE_AGGRESSIVE_REMARK",), expected_sarcasm=True),
        GoldenEvalCase("EVAL-EN-14", "en", "Thanks a lot for nothing when I actually needed your backup.", ("en",), ("SARCASTIC_OR_PASSIVE_AGGRESSIVE_REMARK",), expected_sarcasm=True),
        GoldenEvalCase("EVAL-EN-15", "en", "Fine.", ("en",), ("SARCASTIC_OR_PASSIVE_AGGRESSIVE_REMARK",), expected_sarcasm=True),
        GoldenEvalCase("EVAL-EN-16", "en", "Whatever.", ("en",), ("SARCASTIC_OR_PASSIVE_AGGRESSIVE_REMARK",), expected_sarcasm=True),
        GoldenEvalCase("EVAL-EN-17", "en", "I am never talking to anyone about that betrayal again!", ("en",), ("ACUTE_EMOTIONAL_VENTING",), expected_acute_venting=True),
        GoldenEvalCase("EVAL-EN-18", "en", "This whole arrangement is completely useless and frustrating!", ("en",), ("ACUTE_EMOTIONAL_VENTING",), expected_acute_venting=True),
        GoldenEvalCase("EVAL-EN-19", "en", "Drop everything and join the call immediately ASAP.", ("en",), ("URGENCY_OR_BOUNDARY_PRESSURE",), expected_boundary_pressure=True),
        GoldenEvalCase("EVAL-EN-20", "en", "You must finish this signoff tonight itself, don't make excuses.", ("en",), ("URGENCY_OR_BOUNDARY_PRESSURE",), expected_boundary_pressure=True),
        GoldenEvalCase("EVAL-EN-21", "en", "Dear Dr. Nair, kindly find the attached agenda; sincere regards.", ("en",), expected_formality_range=(0.65, 0.95)),
        GoldenEvalCase("EVAL-EN-22", "en", "Are you free this evening to grab a quick coffee?", ("en",), ("SCHEDULING_COORDINATION", "QUESTION_INQUIRY")),
        GoldenEvalCase("EVAL-EN-23", "en", "I'll drop by the clinic tomorrow morning at 9 AM.", ("en",), ("SCHEDULING_COORDINATION", "COMMITMENT_STATEMENT"), expected_slot_time=True),
        GoldenEvalCase("EVAL-EN-24", "en", "So helpful of you to wait until midnight to mention the flight.", ("en",), ("SARCASTIC_OR_PASSIVE_AGGRESSIVE_REMARK",), expected_sarcasm=True),
        GoldenEvalCase("EVAL-EN-25", "en", "I feel happy and grateful for how smoothly our workshop ran.", ("en",), expected_valence_sign="positive"),
        GoldenEvalCase("EVAL-EN-26", "en", "Yeah right, as if anyone reads the footer notes anymore.", ("en",), ("SARCASTIC_OR_PASSIVE_AGGRESSIVE_REMARK",), expected_sarcasm=True),
        GoldenEvalCase("EVAL-EN-27", "en", "Please reply urgent because the courier leaves at 5 PM.", ("en",), ("URGENCY_OR_BOUNDARY_PRESSURE",), expected_boundary_pressure=True, expected_slot_time=True),
        GoldenEvalCase("EVAL-EN-28", "en", "Did you reach home safely after the rain?", ("en",), ("QUESTION_INQUIRY",)),
        GoldenEvalCase("EVAL-EN-29", "en", "I love how peaceful the campus feels on Sunday mornings.", ("en",), expected_valence_sign="positive"),
        GoldenEvalCase("EVAL-EN-30", "en", "Madam, would 4:15 PM work for our quarterly check-in?", ("en",), ("QUESTION_INQUIRY",), expected_formality_range=(0.55, 0.95), expected_slot_time=True),
    ]


def _build_hi_latn_cases() -> list[GoldenEvalCase]:
    return [
        GoldenEvalCase("EVAL-HI-LATN-01", "hi-Latn", "Kya kar raha hai bhai aaj shaam ko?", ("hi-Latn",), ("QUESTION_INQUIRY",), expected_formality_range=(0.05, 0.35)),
        GoldenEvalCase("EVAL-HI-LATN-02", "hi-Latn", "Aap kaise hain ji? Kal 7 baje baat karte hain.", ("hi-Latn",), ("SCHEDULING_COORDINATION", "QUESTION_INQUIRY"), expected_formality_range=(0.55, 0.90), expected_slot_time=True),
        GoldenEvalCase("EVAL-HI-LATN-03", "hi-Latn", "Bhai abhi ke abhi jawab de aur ghar aa!", ("hi-Latn",), ("URGENCY_OR_BOUNDARY_PRESSURE",), expected_boundary_pressure=True),
        GoldenEvalCase("EVAL-HI-LATN-04", "hi-Latn", "Bahut badhiya kaam kiya yaar, ab bata jab sab bhool gaye!", ("hi-Latn",), ("SARCASTIC_OR_PASSIVE_AGGRESSIVE_REMARK",), expected_sarcasm=True),
        GoldenEvalCase("EVAL-HI-LATN-05", "hi-Latn", "Rehne do.", ("hi-Latn",), ("SARCASTIC_OR_PASSIVE_AGGRESSIVE_REMARK",), expected_sarcasm=True),
        GoldenEvalCase("EVAL-HI-LATN-06", "hi-Latn", "Yaar aaj batti gul ho gayi poora din padh kar.", ("hi-Latn",), expected_idiom=True),
        GoldenEvalCase("EVAL-HI-LATN-07", "hi-Latn", "Kya scene hai kal raat dinner ka bhai?", ("hi-Latn", "en"), ("SCHEDULING_COORDINATION", "QUESTION_INQUIRY"), expected_idiom=True),
        GoldenEvalCase("EVAL-HI-LATN-08", "hi-Latn", "Tu itna bhav kha kyun raha hai yaar aaj?", ("hi-Latn",), ("QUESTION_INQUIRY",), expected_idiom=True),
        GoldenEvalCase("EVAL-HI-LATN-09", "hi-Latn", "Mera dimag kharab mat kar, sab bakwas lag raha hai!", ("hi-Latn",), ("ACUTE_EMOTIONAL_VENTING",), expected_acute_venting=True, expected_valence_sign="negative"),
        GoldenEvalCase("EVAL-HI-LATN-10", "hi-Latn", "Kal milte hain 6 baje chai par dost.", ("hi-Latn",), ("SCHEDULING_COORDINATION", "COMMITMENT_STATEMENT"), expected_slot_time=True),
        GoldenEvalCase("EVAL-HI-LATN-11", "hi-Latn", "Main 9 PM tak report bhejunga bhai.", ("hi-Latn", "en"), ("COMMITMENT_STATEMENT",), expected_slot_time=True),
        GoldenEvalCase("EVAL-HI-LATN-12", "hi-Latn", "Tum abhi ghar par ho ya office mein?", ("hi-Latn", "en"), ("QUESTION_INQUIRY",)),
        GoldenEvalCase("EVAL-HI-LATN-13", "hi-Latn", "Haan bilkul theek hai, kal baat karte hain.", ("hi-Latn",), ("SCHEDULING_COORDINATION",)),
        GoldenEvalCase("EVAL-HI-LATN-14", "hi-Latn", "Didi aap kab aa rahi hain ghar?", ("hi-Latn",), ("QUESTION_INQUIRY",), expected_formality_range=(0.55, 0.90)),
        GoldenEvalCase("EVAL-HI-LATN-15", "hi-Latn", "Bhaiya thoda jaldi batao, meeting 5 PM pe hai!", ("hi-Latn", "en"), ("SCHEDULING_COORDINATION",), expected_slot_time=True),
        GoldenEvalCase("EVAL-HI-LATN-16", "hi-Latn", "Main sirf mazaak kar raha tha yaar.", ("hi-Latn",), expected_idiom=True),
        GoldenEvalCase("EVAL-HI-LATN-17", "hi-Latn", "Bahut achha kiya, late aakar sab kharab kar diya!", ("hi-Latn", "en"), ("SARCASTIC_OR_PASSIVE_AGGRESSIVE_REMARK",), expected_sarcasm=True),
        GoldenEvalCase("EVAL-HI-LATN-18", "hi-Latn", "Aaj kaam bohot zyada hai, kal subah call karunga.", ("hi-Latn", "en"), ("SCHEDULING_COORDINATION", "COMMITMENT_STATEMENT")),
        GoldenEvalCase("EVAL-HI-LATN-19", "hi-Latn", "Tu ghar kab pahunch raha hai?", ("hi-Latn",), ("QUESTION_INQUIRY",)),
        GoldenEvalCase("EVAL-HI-LATN-20", "hi-Latn", "Sab badhiya chal raha hai, bohot accha laga sun kar!", ("hi-Latn",), expected_valence_sign="positive"),
        GoldenEvalCase("EVAL-HI-LATN-21", "hi-Latn", "Chalo kal milte hain aur aaram se baat karte hain.", ("hi-Latn",), ("SCHEDULING_COORDINATION", "COMMITMENT_STATEMENT")),
        GoldenEvalCase("EVAL-HI-LATN-22", "hi-Latn", "Abhi ke abhi call karo, no excuses bhai!", ("hi-Latn", "en"), ("URGENCY_OR_BOUNDARY_PRESSURE",), expected_boundary_pressure=True),
        GoldenEvalCase("EVAL-HI-LATN-23", "hi-Latn", "Bhai yeh kaam aaj nahi ho payega, kal karunga.", ("hi-Latn",), ("COMMITMENT_STATEMENT",)),
        GoldenEvalCase("EVAL-HI-LATN-24", "hi-Latn", "Aap bura mat manna ji, main time par milunga.", ("hi-Latn", "en"), expected_formality_range=(0.55, 0.90)),
        GoldenEvalCase("EVAL-HI-LATN-25", "hi-Latn", "Kahan ho yaar tum abhi?", ("hi-Latn",), ("QUESTION_INQUIRY",)),
        GoldenEvalCase("EVAL-HI-LATN-26", "hi-Latn", "Nahi bhai, aaj bilkul time nahi hai mere paas.", ("hi-Latn", "en")),
        GoldenEvalCase("EVAL-HI-LATN-27", "hi-Latn", "Yeh sab bakwas band karo aur shaant raho!", ("hi-Latn",), ("ACUTE_EMOTIONAL_VENTING",), expected_acute_venting=True),
        GoldenEvalCase("EVAL-HI-LATN-28", "hi-Latn", "Kal shaam 6:30 PM par milte hain?", ("hi-Latn", "en"), ("SCHEDULING_COORDINATION", "QUESTION_INQUIRY"), expected_slot_time=True),
        GoldenEvalCase("EVAL-HI-LATN-29", "hi-Latn", "Kaam kaisa chal raha hai tumhara?", ("hi-Latn",), ("QUESTION_INQUIRY",)),
        GoldenEvalCase("EVAL-HI-LATN-30", "hi-Latn", "Bahut khoob dost, ab bata jab sab chala gaya.", ("hi-Latn",), ("SARCASTIC_OR_PASSIVE_AGGRESSIVE_REMARK",), expected_sarcasm=True),
    ]


def _build_hi_deva_cases() -> list[GoldenEvalCase]:
    return [
        GoldenEvalCase("EVAL-HI-DEVA-01", "hi-Deva", "कहाँ हो भाई, कल 8 बजे मिलना है?", ("hi-Deva",), ("QUESTION_INQUIRY",), expected_slot_time=True),
        GoldenEvalCase("EVAL-HI-DEVA-02", "hi-Deva", "आप कैसे हैं जी? कल समय पर बात करते हैं।", ("hi-Deva",), ("QUESTION_INQUIRY",), expected_formality_range=(0.55, 0.90)),
        GoldenEvalCase("EVAL-HI-DEVA-03", "hi-Deva", "अभी के अभी मुझे रिपोर्ट भेजो!", ("hi-Deva",), ("URGENCY_OR_BOUNDARY_PRESSURE",), expected_boundary_pressure=True),
        GoldenEvalCase("EVAL-HI-DEVA-04", "hi-Deva", "बहुत बढ़िया, अब बता जब मीटिंग खत्म हो गई!", ("hi-Deva",), ("SARCASTIC_OR_PASSIVE_AGGRESSIVE_REMARK",), expected_sarcasm=True),
        GoldenEvalCase("EVAL-HI-DEVA-05", "hi-Deva", "रहने दो।", ("hi-Deva",), ("SARCASTIC_OR_PASSIVE_AGGRESSIVE_REMARK",), expected_sarcasm=True),
        GoldenEvalCase("EVAL-HI-DEVA-06", "hi-Deva", "आज पूरा दिन काम करके दिमाग की बत्ती गुल हो गई।", ("hi-Deva",), expected_idiom=True),
        GoldenEvalCase("EVAL-HI-DEVA-07", "hi-Deva", "कल शाम का क्या सीन है भाई?", ("hi-Deva",), ("QUESTION_INQUIRY",), expected_idiom=True),
        GoldenEvalCase("EVAL-HI-DEVA-08", "hi-Deva", "इतना भाव खा क्यों रहे हो आज?", ("hi-Deva",), ("QUESTION_INQUIRY",), expected_idiom=True),
        GoldenEvalCase("EVAL-HI-DEVA-09", "hi-Deva", "मेरा दिमाग खराब हो रहा है इस रोज़ के झगड़े से!", ("hi-Deva",), ("ACUTE_EMOTIONAL_VENTING",), expected_acute_venting=True),
        GoldenEvalCase("EVAL-HI-DEVA-10", "hi-Deva", "कल सुबह 9 बजे मिलते हैं।", ("hi-Deva",), ("SCHEDULING_COORDINATION",), expected_slot_time=True),
        GoldenEvalCase("EVAL-HI-DEVA-11", "hi-Deva", "मैं रात तक सारा काम भेजूंगा।", ("hi-Deva",), ("COMMITMENT_STATEMENT",)),
        GoldenEvalCase("EVAL-HI-DEVA-12", "hi-Deva", "दीदी आप कब घर पहुँच रही हैं?", ("hi-Deva",), ("QUESTION_INQUIRY",), expected_formality_range=(0.55, 0.90)),
        GoldenEvalCase("EVAL-HI-DEVA-13", "hi-Deva", "भैया शाम 6 बजे कॉल करेंगे क्या?", ("hi-Deva",), ("QUESTION_INQUIRY",), expected_slot_time=True),
        GoldenEvalCase("EVAL-HI-DEVA-14", "hi-Deva", "सब बहुत बढ़िया रहा, सुनकर खुशी हुई!", ("hi-Deva",), expected_valence_sign="positive"),
        GoldenEvalCase("EVAL-HI-DEVA-15", "hi-Deva", "कब आना है तुम्हें कॉलेज?", ("hi-Deva",), ("QUESTION_INQUIRY",)),
        GoldenEvalCase("EVAL-HI-DEVA-16", "hi-Deva", "तुम बस मज़ाक कर रहे हो न यार?", ("hi-Deva",), ("QUESTION_INQUIRY",), expected_idiom=True),
        GoldenEvalCase("EVAL-HI-DEVA-17", "hi-Deva", "कल शाम को मिलते हैं आराम से।", ("hi-Deva",), ("SCHEDULING_COORDINATION", "COMMITMENT_STATEMENT")),
        GoldenEvalCase("EVAL-HI-DEVA-18", "hi-Deva", "यार आज थोड़ा व्यस्त हूँ, कल बात करेंगे।", ("hi-Deva",), expected_formality_range=(0.05, 0.35)),
        GoldenEvalCase("EVAL-HI-DEVA-19", "hi-Deva", "जी बिल्कुल, मैं कल 10 बजे कॉल करूँगा।", ("hi-Deva",), expected_formality_range=(0.55, 0.90), expected_slot_time=True),
        GoldenEvalCase("EVAL-HI-DEVA-20", "hi-Deva", "अभी के अभी फोन उठाओ भाई!", ("hi-Deva",), ("URGENCY_OR_BOUNDARY_PRESSURE",), expected_boundary_pressure=True),
        GoldenEvalCase("EVAL-HI-DEVA-21", "hi-Deva", "आपका दिन शुभ हो जी।", ("hi-Deva",), expected_formality_range=(0.55, 0.90)),
        GoldenEvalCase("EVAL-HI-DEVA-22", "hi-Deva", "क्या आज शाम को चाय पर मिलें?", ("hi-Deva",), ("QUESTION_INQUIRY",)),
        GoldenEvalCase("EVAL-HI-DEVA-23", "hi-Deva", "कल सुबह 7 बजे तैयार रहना, मिलते हैं।", ("hi-Deva",), ("SCHEDULING_COORDINATION",), expected_slot_time=True),
        GoldenEvalCase("EVAL-HI-DEVA-24", "hi-Deva", "तू इतना परेशान क्यों है यार?", ("hi-Deva",), ("QUESTION_INQUIRY",)),
        GoldenEvalCase("EVAL-HI-DEVA-25", "hi-Deva", "माफ़ करना, आज देर हो गई।", ("hi-Deva",)),
        GoldenEvalCase("EVAL-HI-DEVA-26", "hi-Deva", "खाना खा लिया तुमने घर पर?", ("hi-Deva",), ("QUESTION_INQUIRY",)),
        GoldenEvalCase("EVAL-HI-DEVA-27", "hi-Deva", "कल का प्रोजेक्ट अपडेट प्लीज भेजो urgent है।", ("hi-Deva", "en"), ("SCHEDULING_COORDINATION", "URGENCY_OR_BOUNDARY_PRESSURE"), expected_boundary_pressure=True),
        GoldenEvalCase("EVAL-HI-DEVA-28", "hi-Deva", "मैं कल 5 PM पर फोन करूंगा।", ("hi-Deva", "en"), expected_slot_time=True),
        GoldenEvalCase("EVAL-HI-DEVA-29", "hi-Deva", "अरे वाह, तुम ठीक हो न दोस्त?", ("hi-Deva",), ("QUESTION_INQUIRY",)),
        GoldenEvalCase("EVAL-HI-DEVA-30", "hi-Deva", "भैया आप कब वापस आएंगे?", ("hi-Deva",), ("QUESTION_INQUIRY",), expected_formality_range=(0.55, 0.90)),
    ]


def _build_ml_latn_cases() -> list[GoldenEvalCase]:
    return [
        GoldenEvalCase("EVAL-ML-LATN-01", "ml-Latn", "Eda nale rathri 8 manikku call cheyyamo?", ("ml-Latn", "en"), ("SCHEDULING_COORDINATION", "QUESTION_INQUIRY"), expected_formality_range=(0.05, 0.35), expected_slot_time=True),
        GoldenEvalCase("EVAL-ML-LATN-02", "ml-Latn", "Ningal eppo veetil ethum chechi?", ("ml-Latn",), ("QUESTION_INQUIRY",), expected_formality_range=(0.55, 0.90)),
        GoldenEvalCase("EVAL-ML-LATN-03", "ml-Latn", "Eda ippo thanne reply tharanam!", ("ml-Latn", "en"), ("URGENCY_OR_BOUNDARY_PRESSURE",), expected_boundary_pressure=True),
        GoldenEvalCase("EVAL-ML-LATN-04", "ml-Latn", "Valare nannayi aliya, ippozhano parayunnath?", ("ml-Latn",), ("SARCASTIC_OR_PASSIVE_AGGRESSIVE_REMARK",), expected_sarcasm=True),
        GoldenEvalCase("EVAL-ML-LATN-05", "ml-Latn", "Sheri enna.", ("ml-Latn",), ("SARCASTIC_OR_PASSIVE_AGGRESSIVE_REMARK",), expected_sarcasm=True),
        GoldenEvalCase("EVAL-ML-LATN-06", "ml-Latn", "Machane avide motham scene contra aayi.", ("ml-Latn",), expected_idiom=True),
        GoldenEvalCase("EVAL-ML-LATN-07", "ml-Latn", "Adipoli presentation machane, pwoli sadhanam!", ("ml-Latn", "en"), expected_idiom=True, expected_valence_sign="positive"),
        GoldenEvalCase("EVAL-ML-LATN-08", "ml-Latn", "Eda avan enikku theppu thannu.", ("ml-Latn",), expected_idiom=True),
        GoldenEvalCase("EVAL-ML-LATN-09", "ml-Latn", "Onnum parayanda aliya, valya budhimuttayi.", ("ml-Latn",), expected_idiom=True),
        GoldenEvalCase("EVAL-ML-LATN-10", "ml-Latn", "Ini mindilla njan, veruthu poyi!", ("ml-Latn",), ("ACUTE_EMOTIONAL_VENTING",), expected_acute_venting=True, expected_idiom=True),
        GoldenEvalCase("EVAL-ML-LATN-11", "ml-Latn", "Nale rathri 9 manikku vilikkam eda.", ("ml-Latn",), ("SCHEDULING_COORDINATION", "COMMITMENT_STATEMENT"), expected_slot_time=True),
        GoldenEvalCase("EVAL-ML-LATN-12", "ml-Latn", "Evideya nee ippo machane?", ("ml-Latn",), ("QUESTION_INQUIRY",)),
        GoldenEvalCase("EVAL-ML-LATN-13", "ml-Latn", "Njan veettil ethi pinne vilikkam.", ("ml-Latn",), ("COMMITMENT_STATEMENT",)),
        GoldenEvalCase("EVAL-ML-LATN-14", "ml-Latn", "Bhakshanam kazhinjo chetta?", ("ml-Latn",), ("QUESTION_INQUIRY",), expected_formality_range=(0.55, 0.90)),
        GoldenEvalCase("EVAL-ML-LATN-15", "ml-Latn", "Office-il meeting kazhinjo eda?", ("ml-Latn", "en"), ("SCHEDULING_COORDINATION", "QUESTION_INQUIRY")),
        GoldenEvalCase("EVAL-ML-LATN-16", "ml-Latn", "Theerchayayum njan nale varaam chechi.", ("ml-Latn",), ("COMMITMENT_STATEMENT",), expected_formality_range=(0.55, 0.90)),
        GoldenEvalCase("EVAL-ML-LATN-17", "ml-Latn", "Sukhamano ningalkku avide?", ("ml-Latn",), ("QUESTION_INQUIRY",), expected_formality_range=(0.55, 0.90)),
        GoldenEvalCase("EVAL-ML-LATN-18", "ml-Latn", "Nale 7 manikku varumo nee?", ("ml-Latn",), ("SCHEDULING_COORDINATION", "QUESTION_INQUIRY"), expected_slot_time=True),
        GoldenEvalCase("EVAL-ML-LATN-19", "ml-Latn", "Ariyilla eda, nokkam enna.", ("ml-Latn",)),
        GoldenEvalCase("EVAL-ML-LATN-20", "ml-Latn", "Valare nannayi chetta, late aayappo thanne.", ("ml-Latn", "en"), ("SARCASTIC_OR_PASSIVE_AGGRESSIVE_REMARK",), expected_sarcasm=True),
        GoldenEvalCase("EVAL-ML-LATN-21", "ml-Latn", "Njan report nale ravile 10 manikku tharam, cheyyam.", ("ml-Latn", "en"), ("SCHEDULING_COORDINATION", "COMMITMENT_STATEMENT"), expected_slot_time=True),
        GoldenEvalCase("EVAL-ML-LATN-22", "ml-Latn", "Entha karyam edi parayu?", ("ml-Latn",), ("QUESTION_INQUIRY",)),
        GoldenEvalCase("EVAL-ML-LATN-23", "ml-Latn", "Ippo thanne call cheyyu urgent aayi!", ("ml-Latn", "en"), ("URGENCY_OR_BOUNDARY_PRESSURE",), expected_boundary_pressure=True),
        GoldenEvalCase("EVAL-ML-LATN-24", "ml-Latn", "Amma veettil undo mone?", ("ml-Latn",), ("QUESTION_INQUIRY",)),
        GoldenEvalCase("EVAL-ML-LATN-25", "ml-Latn", "Chaya kudicho nee mole?", ("ml-Latn",), ("QUESTION_INQUIRY",)),
        GoldenEvalCase("EVAL-ML-LATN-26", "ml-Latn", "Parayoo chettan eppo ethum?", ("ml-Latn",), ("QUESTION_INQUIRY",), expected_formality_range=(0.55, 0.90)),
        GoldenEvalCase("EVAL-ML-LATN-27", "ml-Latn", "Pinne vilikku machane, ippo thirakkundu.", ("ml-Latn",), expected_formality_range=(0.05, 0.35)),
        GoldenEvalCase("EVAL-ML-LATN-28", "ml-Latn", "Uff enthu budhimuttanu ee karyam.", ("ml-Latn",)),
        GoldenEvalCase("EVAL-ML-LATN-29", "ml-Latn", "Njn nale 6 PM nu varaam office-il.", ("ml-Latn", "en"), ("SCHEDULING_COORDINATION", "COMMITMENT_STATEMENT"), expected_slot_time=True),
        GoldenEvalCase("EVAL-ML-LATN-30", "ml-Latn", "Eppozha exam thudangunnath, parayu?", ("ml-Latn", "en"), ("QUESTION_INQUIRY",)),
    ]


def _build_ml_mlym_cases() -> list[GoldenEvalCase]:
    return [
        GoldenEvalCase("EVAL-ML-MLYM-01", "ml-Mlym", "എടാ നാളെ രാത്രി 8 മണിക്ക് വിളിക്കാം.", ("ml-Mlym",), ("SCHEDULING_COORDINATION", "COMMITMENT_STATEMENT"), expected_formality_range=(0.05, 0.35), expected_slot_time=True),
        GoldenEvalCase("EVAL-ML-MLYM-02", "ml-Mlym", "നിങ്ങൾ എപ്പോൾ വീട്ടിൽ എത്തും ചേച്ചി?", ("ml-Mlym",), ("QUESTION_INQUIRY",), expected_formality_range=(0.55, 0.90)),
        GoldenEvalCase("EVAL-ML-MLYM-03", "ml-Mlym", "ഇപ്പോൾ തന്നെ മറുപടി തരണം!", ("ml-Mlym",), ("URGENCY_OR_BOUNDARY_PRESSURE",), expected_boundary_pressure=True),
        GoldenEvalCase("EVAL-ML-MLYM-04", "ml-Mlym", "വളരെ നന്നായി, ഇപ്പോഴാണോ പറയുന്നത്?", ("ml-Mlym",), ("SARCASTIC_OR_PASSIVE_AGGRESSIVE_REMARK",), expected_sarcasm=True),
        GoldenEvalCase("EVAL-ML-MLYM-05", "ml-Mlym", "ശരി എന്നാ.", ("ml-Mlym",), ("SARCASTIC_OR_PASSIVE_AGGRESSIVE_REMARK",), expected_sarcasm=True),
        GoldenEvalCase("EVAL-ML-MLYM-06", "ml-Mlym", "അവിടെ ആകെ സീൻ കോൺട്ര ആയല്ലോ.", ("ml-Mlym",), expected_idiom=True),
        GoldenEvalCase("EVAL-ML-MLYM-07", "ml-Mlym", "നിന്റെ അവതരണം അടിപൊളി ആയിരുന്നു!", ("ml-Mlym",), expected_idiom=True, expected_valence_sign="positive"),
        GoldenEvalCase("EVAL-ML-MLYM-08", "ml-Mlym", "അവൻ അവസാന നിമിഷം തേപ്പ് തന്നു.", ("ml-Mlym",), expected_idiom=True),
        GoldenEvalCase("EVAL-ML-MLYM-09", "ml-Mlym", "ഒന്നും പറയണ്ട, ആകെ പ്രശ്നമായി.", ("ml-Mlym",), expected_idiom=True),
        GoldenEvalCase("EVAL-ML-MLYM-10", "ml-Mlym", "ഇനി മിണ്ടില്ല ഞാൻ, വെറുത്തു പോയി!", ("ml-Mlym",), ("ACUTE_EMOTIONAL_VENTING",), expected_acute_venting=True, expected_idiom=True),
        GoldenEvalCase("EVAL-ML-MLYM-11", "ml-Mlym", "നാളെ വൈകുന്നേരം 6 മണിക്ക് വരുമോ?", ("ml-Mlym",), ("SCHEDULING_COORDINATION", "QUESTION_INQUIRY"), expected_slot_time=True),
        GoldenEvalCase("EVAL-ML-MLYM-12", "ml-Mlym", "എവിടെയാ നീ ഇപ്പോൾ എടാ?", ("ml-Mlym",), ("QUESTION_INQUIRY",)),
        GoldenEvalCase("EVAL-ML-MLYM-13", "ml-Mlym", "ഞാൻ കുറച്ച് കഴിഞ്ഞു വിളിക്കാം.", ("ml-Mlym",), ("SCHEDULING_COORDINATION", "COMMITMENT_STATEMENT")),
        GoldenEvalCase("EVAL-ML-MLYM-14", "ml-Mlym", "ഭക്ഷണം കഴിച്ചോ ചേട്ടൻ?", ("ml-Mlym",), ("QUESTION_INQUIRY",), expected_formality_range=(0.55, 0.90)),
        GoldenEvalCase("EVAL-ML-MLYM-15", "ml-Mlym", "നാളെ ഞാൻ തീർച്ചയായും വരാം.", ("ml-Mlym",), ("SCHEDULING_COORDINATION", "COMMITMENT_STATEMENT")),
        GoldenEvalCase("EVAL-ML-MLYM-16", "ml-Mlym", "ഇന്ന് രാത്രി 9 മണിക്ക് സംസാരിക്കാം.", ("ml-Mlym",), ("SCHEDULING_COORDINATION",), expected_slot_time=True),
        GoldenEvalCase("EVAL-ML-MLYM-17", "ml-Mlym", "അമ്മ വീട്ടിൽ സുഖമായി ഇരിക്കുന്നുണ്ടോ?", ("ml-Mlym",), ("QUESTION_INQUIRY",)),
        GoldenEvalCase("EVAL-ML-MLYM-18", "ml-Mlym", "നീ നാളെ കോളേജിൽ ചെയ്യാമോ?", ("ml-Mlym",), ("SCHEDULING_COORDINATION", "QUESTION_INQUIRY")),
        GoldenEvalCase("EVAL-ML-MLYM-19", "ml-Mlym", "ഇന്ന് project തിരക്ക് ഉണ്ട്, നാളെ സംസാരിക്കാം.", ("ml-Mlym", "en"), ("SCHEDULING_COORDINATION",)),
        GoldenEvalCase("EVAL-ML-MLYM-20", "ml-Mlym", "എടി എപ്പോൾ എത്തും നീ വീട്ടിൽ?", ("ml-Mlym",), ("QUESTION_INQUIRY",)),
        GoldenEvalCase("EVAL-ML-MLYM-21", "ml-Mlym", "മച്ചാനെ ഇന്ന് രാത്രി 10 മണിക്ക് കാണാം.", ("ml-Mlym",), ("SCHEDULING_COORDINATION",), expected_slot_time=True),
        GoldenEvalCase("EVAL-ML-MLYM-22", "ml-Mlym", "ഇപ്പോൾ തന്നെ വരാൻ പറ്റുമോ?", ("ml-Mlym",), ("URGENCY_OR_BOUNDARY_PRESSURE", "QUESTION_INQUIRY"), expected_boundary_pressure=True),
        GoldenEvalCase("EVAL-ML-MLYM-23", "ml-Mlym", "ചേച്ചി നാളെ രാവിലെ വിളിക്കാമോ?", ("ml-Mlym",), ("SCHEDULING_COORDINATION",), expected_formality_range=(0.55, 0.90)),
        GoldenEvalCase("EVAL-ML-MLYM-24", "ml-Mlym", "വൈകുന്നേരം 5 മണിക്ക് ഞാൻ വരാം.", ("ml-Mlym",), ("COMMITMENT_STATEMENT",), expected_slot_time=True),
        GoldenEvalCase("EVAL-ML-MLYM-25", "ml-Mlym", "എല്ലാം അടിപൊളി ആയി നടന്നു!", ("ml-Mlym",), expected_idiom=True, expected_valence_sign="positive"),
        GoldenEvalCase("EVAL-ML-MLYM-26", "ml-Mlym", "ഇനി ഞാൻ ഒന്നും ചെയ്യാം എന്ന് പറയുന്നില്ല, വെറുത്തു പോയി!", ("ml-Mlym",), ("ACUTE_EMOTIONAL_VENTING",), expected_acute_venting=True),
        GoldenEvalCase("EVAL-ML-MLYM-27", "ml-Mlym", "അച്ഛൻ വീട്ടിൽ എത്തിയോ?", ("ml-Mlym",), ("QUESTION_INQUIRY",)),
        GoldenEvalCase("EVAL-ML-MLYM-28", "ml-Mlym", "രാത്രി 8 മണിക്ക് call ചെയ്യാം.", ("ml-Mlym", "en"), ("SCHEDULING_COORDINATION", "COMMITMENT_STATEMENT"), expected_slot_time=True),
        GoldenEvalCase("EVAL-ML-MLYM-29", "ml-Mlym", "സുഖമാണോ നിങ്ങൾക്ക് അവിടെ?", ("ml-Mlym",), ("QUESTION_INQUIRY",), expected_formality_range=(0.55, 0.90)),
        GoldenEvalCase("EVAL-ML-MLYM-30", "ml-Mlym", "നാളെ meeting 7 മണിക്ക് ആണോ?", ("ml-Mlym", "en"), ("SCHEDULING_COORDINATION", "QUESTION_INQUIRY"), expected_slot_time=True),
    ]


def _build_te_latn_cases() -> list[GoldenEvalCase]:
    return [
        GoldenEvalCase("EVAL-TE-LATN-01", "te-Latn", "Ekkada unnava ra nuvvu ippati varaku?", ("te-Latn",), ("QUESTION_INQUIRY",), expected_formality_range=(0.05, 0.35)),
        GoldenEvalCase("EVAL-TE-LATN-02", "te-Latn", "Meeru repu intiki vastara garu?", ("te-Latn",), ("SCHEDULING_COORDINATION", "QUESTION_INQUIRY"), expected_formality_range=(0.55, 0.90)),
        GoldenEvalCase("EVAL-TE-LATN-03", "te-Latn", "Ippude chey ra ledu ante avvadu!", ("te-Latn",), ("URGENCY_OR_BOUNDARY_PRESSURE",), expected_boundary_pressure=True),
        GoldenEvalCase("EVAL-TE-LATN-04", "te-Latn", "Chala goppaga cheppav le anna, ippatiki gurthochinda?", ("te-Latn",), ("SARCASTIC_OR_PASSIVE_AGGRESSIVE_REMARK",), expected_sarcasm=True),
        GoldenEvalCase("EVAL-TE-LATN-05", "te-Latn", "Sare le.", ("te-Latn",), ("SARCASTIC_OR_PASSIVE_AGGRESSIVE_REMARK",), expected_sarcasm=True),
        GoldenEvalCase("EVAL-TE-LATN-06", "te-Latn", "Light teesko ra mama, anni set avuthayi.", ("en", "te-Latn"), expected_idiom=True),
        GoldenEvalCase("EVAL-TE-LATN-07", "te-Latn", "Pedda bisket vesav kada ra nuvvu!", ("te-Latn",), expected_idiom=True),
        GoldenEvalCase("EVAL-TE-LATN-08", "te-Latn", "Chala bagundi ra nee work, super!", ("te-Latn", "en"), expected_idiom=True, expected_valence_sign="positive"),
        GoldenEvalCase("EVAL-TE-LATN-09", "te-Latn", "Em chestam andi, konchem wait cheyali.", ("te-Latn", "en"), expected_idiom=True),
        GoldenEvalCase("EVAL-TE-LATN-10", "te-Latn", "Chiraku vastundi naaku ee godava tho!", ("te-Latn",), ("ACUTE_EMOTIONAL_VENTING",), expected_acute_venting=True),
        GoldenEvalCase("EVAL-TE-LATN-11", "te-Latn", "Repu 8 PM ki kaluddam anna.", ("te-Latn", "en"), ("SCHEDULING_COORDINATION",), expected_slot_time=True),
        GoldenEvalCase("EVAL-TE-LATN-12", "te-Latn", "Nenu intiki vastunna, 6 gantalaku chestha.", ("te-Latn",), ("COMMITMENT_STATEMENT",), expected_slot_time=True),
        GoldenEvalCase("EVAL-TE-LATN-13", "te-Latn", "Tinnava ra nuvvu?", ("te-Latn",), ("QUESTION_INQUIRY",)),
        GoldenEvalCase("EVAL-TE-LATN-14", "te-Latn", "Meeru bagunnara akka?", ("te-Latn",), ("QUESTION_INQUIRY",), expected_formality_range=(0.55, 0.90)),
        GoldenEvalCase("EVAL-TE-LATN-15", "te-Latn", "Eppudu vastava intiki repu?", ("te-Latn",), ("SCHEDULING_COORDINATION", "QUESTION_INQUIRY")),
        GoldenEvalCase("EVAL-TE-LATN-16", "te-Latn", "Avunu andi, nenu repu 9 AM ki vastha.", ("te-Latn", "en"), ("SCHEDULING_COORDINATION", "COMMITMENT_STATEMENT"), expected_slot_time=True),
        GoldenEvalCase("EVAL-TE-LATN-17", "te-Latn", "Kaadu ra, ellundi kaluddam manam.", ("te-Latn",), ("SCHEDULING_COORDINATION",)),
        GoldenEvalCase("EVAL-TE-LATN-18", "te-Latn", "Cheppandi garu, emi chestunnaru meeru?", ("te-Latn",), ("QUESTION_INQUIRY",), expected_formality_range=(0.55, 0.90)),
        GoldenEvalCase("EVAL-TE-LATN-19", "te-Latn", "Office-lo meeting eppudu babu?", ("te-Latn", "en"), ("SCHEDULING_COORDINATION", "QUESTION_INQUIRY")),
        GoldenEvalCase("EVAL-TE-LATN-20", "te-Latn", "Nenu ivala busy ga unna, repu veldham.", ("te-Latn", "en"), ("SCHEDULING_COORDINATION",)),
        GoldenEvalCase("EVAL-TE-LATN-21", "te-Latn", "Enduku ra late chesava?", ("te-Latn", "en"), ("QUESTION_INQUIRY",)),
        GoldenEvalCase("EVAL-TE-LATN-22", "te-Latn", "Leru andi, repu podunna unnaru.", ("te-Latn",), expected_formality_range=(0.55, 0.90)),
        GoldenEvalCase("EVAL-TE-LATN-23", "te-Latn", "Nuvvu ekada chesthunnav job?", ("te-Latn", "en"), ("QUESTION_INQUIRY",)),
        GoldenEvalCase("EVAL-TE-LATN-24", "te-Latn", "Chala bagundi garu, chaala thanks.", ("te-Latn", "en"), expected_idiom=True, expected_valence_sign="positive"),
        GoldenEvalCase("EVAL-TE-LATN-25", "te-Latn", "Lite teesko mama, tension vaddu.", ("te-Latn", "en"), expected_idiom=True),
        GoldenEvalCase("EVAL-TE-LATN-26", "te-Latn", "Meeru call chestunnaru ani cheppu andi.", ("te-Latn", "en"), ("SCHEDULING_COORDINATION",), expected_formality_range=(0.55, 0.90)),
        GoldenEvalCase("EVAL-TE-LATN-27", "te-Latn", "Eppudu ra intlo untava repu 7 gantalaku?", ("te-Latn",), ("SCHEDULING_COORDINATION", "QUESTION_INQUIRY"), expected_slot_time=True),
        GoldenEvalCase("EVAL-TE-LATN-28", "te-Latn", "Chala goppaga undi nee plan, kani work avvadu!", ("te-Latn", "en"), ("SARCASTIC_OR_PASSIVE_AGGRESSIVE_REMARK",), expected_sarcasm=True),
        GoldenEvalCase("EVAL-TE-LATN-29", "te-Latn", "Ippude chey urgent ga unna!", ("te-Latn", "en"), ("URGENCY_OR_BOUNDARY_PRESSURE",), expected_boundary_pressure=True),
        GoldenEvalCase("EVAL-TE-LATN-30", "te-Latn", "Chesava ra work nuvvu?", ("te-Latn", "en"), ("QUESTION_INQUIRY",)),
    ]


def _build_te_telu_cases() -> list[GoldenEvalCase]:
    return [
        GoldenEvalCase("EVAL-TE-TELU-01", "te-Telu", "ఎక్కడ ఉన్నావు రా నువ్వు ఇప్పుడు?", ("te-Telu",), ("QUESTION_INQUIRY",), expected_formality_range=(0.05, 0.35)),
        GoldenEvalCase("EVAL-TE-TELU-02", "te-Telu", "మీరు రేపు సాయంత్రం 6 గంటలకు వస్తారా గారు?", ("te-Telu",), ("SCHEDULING_COORDINATION", "QUESTION_INQUIRY"), expected_formality_range=(0.55, 0.90), expected_slot_time=True),
        GoldenEvalCase("EVAL-TE-TELU-03", "te-Telu", "ఇప్పుడే నాకు సమాధానం పంపాలి!", ("te-Telu",), ("URGENCY_OR_BOUNDARY_PRESSURE",), expected_boundary_pressure=True),
        GoldenEvalCase("EVAL-TE-TELU-04", "te-Telu", "చాలా గొప్పగా చెప్పావ్ లే, ఇప్పుడు గుర్తొచ్చిందా!", ("te-Telu",), ("SARCASTIC_OR_PASSIVE_AGGRESSIVE_REMARK",), expected_sarcasm=True),
        GoldenEvalCase("EVAL-TE-TELU-05", "te-Telu", "సరే లే.", ("te-Telu",), ("SARCASTIC_OR_PASSIVE_AGGRESSIVE_REMARK",), expected_sarcasm=True),
        GoldenEvalCase("EVAL-TE-TELU-06", "te-Telu", "లైట్ తీసుకో రా మామ, అంతా సర్దుకుంటుంది.", ("te-Telu",), expected_idiom=True),
        GoldenEvalCase("EVAL-TE-TELU-07", "te-Telu", "పెద్ద బిస్కెట్ వేసావు కదా!", ("te-Telu",), expected_idiom=True),
        GoldenEvalCase("EVAL-TE-TELU-08", "te-Telu", "నీ పని చాలా బాగుంది అన్నా!", ("te-Telu",), expected_idiom=True, expected_valence_sign="positive"),
        GoldenEvalCase("EVAL-TE-TELU-09", "te-Telu", "ఏం చేస్తాం అండి, రేపు మళ్ళీ చూద్దాం.", ("te-Telu",), expected_idiom=True),
        GoldenEvalCase("EVAL-TE-TELU-10", "te-Telu", "ఈ గొడవతో నాకు చిరాకు వస్తోంది!", ("te-Telu",), ("ACUTE_EMOTIONAL_VENTING",), expected_acute_venting=True),
        GoldenEvalCase("EVAL-TE-TELU-11", "te-Telu", "రేపు 8 గంటలకు కలుద్దాం అన్నా.", ("te-Telu",), ("SCHEDULING_COORDINATION",), expected_slot_time=True),
        GoldenEvalCase("EVAL-TE-TELU-12", "te-Telu", "నేను ఇంటికి వస్తాను రేపు ఉదయం.", ("te-Telu",), ("SCHEDULING_COORDINATION", "COMMITMENT_STATEMENT")),
        GoldenEvalCase("EVAL-TE-TELU-13", "te-Telu", "తిన్నావా నువ్వు భోజనం?", ("te-Telu",), ("QUESTION_INQUIRY",)),
        GoldenEvalCase("EVAL-TE-TELU-14", "te-Telu", "అక్క మీరు బాగున్నారా అండి?", ("te-Telu",), ("QUESTION_INQUIRY",), expected_formality_range=(0.55, 0.90)),
        GoldenEvalCase("EVAL-TE-TELU-15", "te-Telu", "ఎప్పుడు వస్తావా ఇంటికి ఈరోజు?", ("te-Telu",), ("QUESTION_INQUIRY",)),
        GoldenEvalCase("EVAL-TE-TELU-16", "te-Telu", "రేపు 7 గంటలకు నేను పని చేస్తా.", ("te-Telu",), ("SCHEDULING_COORDINATION", "COMMITMENT_STATEMENT"), expected_slot_time=True),
        GoldenEvalCase("EVAL-TE-TELU-17", "te-Telu", "మీరు రేపు office కి వస్తారా?", ("te-Telu", "en"), ("SCHEDULING_COORDINATION",)),
        GoldenEvalCase("EVAL-TE-TELU-18", "te-Telu", "మామ ఇవాళ 9 PM కి కాల్ చెయ్.", ("te-Telu", "en"), ("SCHEDULING_COORDINATION",), expected_slot_time=True),
        GoldenEvalCase("EVAL-TE-TELU-19", "te-Telu", "బాగున్నాను అన్నా, ధన్యవాదాలు.", ("te-Telu",), expected_formality_range=(0.55, 0.90)),
        GoldenEvalCase("EVAL-TE-TELU-20", "te-Telu", "ఇప్పుడే call చెయ్యాలి అన్నా!", ("te-Telu", "en"), ("URGENCY_OR_BOUNDARY_PRESSURE",), expected_boundary_pressure=True),
        GoldenEvalCase("EVAL-TE-TELU-21", "te-Telu", "సాయంత్రం 5 గంటలకు మాట్లాడుకుందాం.", ("te-Telu",), expected_slot_time=True),
        GoldenEvalCase("EVAL-TE-TELU-22", "te-Telu", "నాన్న ఇంటికి వచ్చారా?", ("te-Telu",), ("QUESTION_INQUIRY",)),
        GoldenEvalCase("EVAL-TE-TELU-23", "te-Telu", "అలాగే గారు, రేపు మళ్ళీ చూస్తాను.", ("te-Telu",), expected_formality_range=(0.55, 0.90)),
        GoldenEvalCase("EVAL-TE-TELU-24", "te-Telu", "ఎక్కడ కలుద్దాం మనం రా?", ("te-Telu",), ("QUESTION_INQUIRY",)),
        GoldenEvalCase("EVAL-TE-TELU-25", "te-Telu", "చాలా బాగుంది అండి ఈ పుస్తకం!", ("te-Telu",), expected_idiom=True, expected_valence_sign="positive"),
        GoldenEvalCase("EVAL-TE-TELU-26", "te-Telu", "ప్రశాంతంగా మాట్లాడుకుని పరిష్కరించుకుందాం.", ("te-Telu",)),
        GoldenEvalCase("EVAL-TE-TELU-27", "te-Telu", "ఈరోజు కొంచెం పనిలో ఉన్నాను, రేపు 10 గంటలకు కాల్ చేస్తా.", ("te-Telu",), ("SCHEDULING_COORDINATION",), expected_slot_time=True),
        GoldenEvalCase("EVAL-TE-TELU-28", "te-Telu", "మీరు ఎలా ఉన్నారు గారు?", ("te-Telu",), ("QUESTION_INQUIRY",), expected_formality_range=(0.55, 0.90)),
        GoldenEvalCase("EVAL-TE-TELU-29", "te-Telu", "నాకు ఈ రోజు చాలా చిరాకుగా ఉంది!", ("te-Telu",), ("ACUTE_EMOTIONAL_VENTING",), expected_acute_venting=True),
        GoldenEvalCase("EVAL-TE-TELU-30", "te-Telu", "సరే అన్నా, రేపు ఉదయం 8 గంటలకు వస్తా.", ("te-Telu",), ("SCHEDULING_COORDINATION", "COMMITMENT_STATEMENT"), expected_slot_time=True),
    ]


GOLDEN_MULTILINGUAL_CORPUS: tuple[GoldenEvalCase, ...] = tuple(
    _build_en_cases()
    + _build_hi_latn_cases()
    + _build_hi_deva_cases()
    + _build_ml_latn_cases()
    + _build_ml_mlym_cases()
    + _build_te_latn_cases()
    + _build_te_telu_cases()
)


def evaluate_golden_corpus(
    pragmatics: MultilingualPragmaticsEngine | None = None,
) -> dict[str, Any]:
    """Evaluates the complete 210-case golden corpus across all 7 authorized modes (`AC-01`, `AC-03`)."""
    engine = pragmatics or MultilingualPragmaticsEngine()
    per_mode: dict[str, dict[str, Any]] = {
        mode: {"total": 0, "passed": 0, "accuracy": 0.0}
        for mode in sorted(AUTHORIZED_LANGUAGE_MODES)
    }
    failures: list[dict[str, Any]] = []
    ac01_all_passed = True

    for case in GOLDEN_MULTILINGUAL_CORPUS:
        per_mode[case.target_mode]["total"] += 1
        reasons: list[str] = []

        analysis = engine.analyze_message(case.raw_text)

        # AC-01 verbatim SHA-256 preservation
        if compute_sha256_hex(case.raw_text) != compute_sha256_hex(analysis.raw_text_verbatim):
            ac01_all_passed = False
            reasons.append("AC-01 verbatim SHA-256 mismatch")

        # 7-mode detection & zero out_of_scope leak
        if analysis.has_out_of_scope_script:
            reasons.append("Unexpected out_of_scope script detected")
        if set(analysis.detected_language_modes) != set(case.expected_detected_modes):
            reasons.append(
                f"Mode mismatch: expected={case.expected_detected_modes}, got={tuple(analysis.detected_language_modes)}"
            )

        for req_act in case.expected_speech_acts:
            if req_act not in analysis.speech_acts:
                reasons.append(f"Missing speech_act '{req_act}' in {analysis.speech_acts}")

        if case.expected_sarcasm is not None and analysis.sarcasm_detected != case.expected_sarcasm:
            reasons.append(f"Sarcasm mismatch: expected={case.expected_sarcasm}, got={analysis.sarcasm_detected}")
        if case.expected_idiom is not None and analysis.idiom_detected != case.expected_idiom:
            reasons.append(f"Idiom mismatch: expected={case.expected_idiom}, got={analysis.idiom_detected}")
        if case.expected_acute_venting is not None and analysis.acute_venting_detected != case.expected_acute_venting:
            reasons.append(f"Acute venting mismatch: expected={case.expected_acute_venting}, got={analysis.acute_venting_detected}")
        if case.expected_boundary_pressure is not None and analysis.boundary_pressure_detected != case.expected_boundary_pressure:
            reasons.append(f"Boundary pressure mismatch: expected={case.expected_boundary_pressure}, got={analysis.boundary_pressure_detected}")
        if case.expected_formality_range is not None:
            lo, hi = case.expected_formality_range
            if not (lo <= analysis.formality_estimate <= hi):
                reasons.append(f"Formality {analysis.formality_estimate} outside [{lo}, {hi}]")
        if case.expected_valence_sign is not None:
            if case.expected_valence_sign == "positive" and analysis.emotional_valence <= 0.2:
                reasons.append(f"Expected positive valence, got {analysis.emotional_valence}")
            elif case.expected_valence_sign == "negative" and analysis.emotional_valence >= -0.1:
                reasons.append(f"Expected negative valence, got {analysis.emotional_valence}")
        if case.expected_slot_time:
            slots = extract_contextual_slots(case.raw_text)
            if not slots["time_mentions"]:
                reasons.append("Expected clock time slot extraction, got empty")

        if not reasons:
            per_mode[case.target_mode]["passed"] += 1
        else:
            failures.append(
                {
                    "case_id": case.case_id,
                    "target_mode": case.target_mode,
                    "raw_text": case.raw_text,
                    "reasons": reasons,
                }
            )

    total = len(GOLDEN_MULTILINGUAL_CORPUS)
    passed = sum(m["passed"] for m in per_mode.values())
    for m_stats in per_mode.values():
        m_total = m_stats["total"]
        m_stats["accuracy"] = round(m_stats["passed"] / m_total, 4) if m_total else 0.0

    overall_accuracy = round(passed / total, 4) if total else 0.0
    ac03_ok = (
        total == 210
        and overall_accuracy >= 0.95
        and all(m["accuracy"] >= 0.90 for m in per_mode.values())
    )
    return {
        "total_cases": total,
        "passed_cases": passed,
        "failed_cases": len(failures),
        "accuracy": overall_accuracy,
        "per_mode_stats": per_mode,
        "ac01_verbatim_sha256_all_passed": ac01_all_passed,
        "ac03_meets_95pct_threshold": ac03_ok,
        "failures": failures,
    }
