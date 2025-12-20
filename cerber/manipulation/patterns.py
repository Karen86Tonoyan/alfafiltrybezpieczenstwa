"""
Manipulation Pattern Database

Source: "Podręcznik Antymanipulacyjny" - Części II & III
Patterns extracted from real-world manipulation techniques.
"""

import re
from typing import List, Dict, Any

# Część II: Atlas Manipulacji - Gaslighting
GASLIGHTING_PATTERNS = [
    # Denial of reality
    r"nigdy (tego )?nie (powiedzia|robi|mówi)",
    r"(to )?nie powiedzia(łem|łam|łeś|łaś)",
    r"wcale (tego )?nie (robi|mówi)",

    # Memory questioning
    r"(sobie )?wyobraziłe(ś|ś)",
    r"(to )?przyśniło ci się",
    r"pamiętasz (to )?źle",
    r"mylisz (się|coś)",

    # Emotional invalidation
    r"jesteś (zbyt|za bardzo) (wrażliw|czuł)",
    r"przesadzasz",
    r"robisz z igły widły",
    r"dramatyzujesz",

    # Normalization
    r"wszyscy tak (robią|mówią)",
    r"to (jest )?normalne",
    r"każdy by tak (zrobił|powiedział)",
]

# Część II: Love Bombing
LOVE_BOMBING_PATTERNS = [
    # Idealization
    r"jesteś (moim )?(ideałem|aniołem|wszystkim)",
    r"(nigdy nie )?spotka(łem|łam) (kogoś )?tak(iego)? jak ty",
    r"jesteś (najlepszym|najwspanialszym|wyjątkowym)",
    r"nikt (inny )?nie (rozumie|kocha) (mnie )?jak ty",

    # Intensity markers
    r"bratnia dusza",
    r"przeznacze(nie|nia)",
    r"od pierwszego (wejrzenia|razu)",
    r"stworze(ni|nia) dla siebie",

    # Excessive gifts/attention
    r"(tylko|wyłącznie) dla ciebie",
    r"zasługujesz na wszystko",
]

# Część III: 6 Reguł Cialdiniego - Ciemna Strona

# 1. Reciprocity (Wzajemność)
RECIPROCITY_EXPLOIT = [
    r"(po tym )?co dla ciebie (zrobi|robi)",
    r"pomog(łem|łam) ci (więc|to)",
    r"(teraz )?jesteś mi (winny|winna|dłużny|dłużna)",
    r"(przecież )?coś za coś",
]

# 2. Consistency (Konsekwencja)
CONSISTENCY_EXPLOIT = [
    r"(przecież )?sam(a)? (powiedzia|mówi)(łeś|łaś)",
    r"(już )?(się )?zgodziłe(ś|ś) (wcześniej)?",
    r"nie możesz teraz (się )?wycofać",
    r"(ale )?obiecałe(ś|ś)",
]

# 3. Social Proof (Dowód Społeczny)
SOCIAL_PROOF_EXPLOIT = [
    r"wszyscy (inni )?(to )?robią",
    r"(każdy|nikt) (nie )?(robi|akceptuje|zgadza się)",
    r"\d+ (osób|ludzi|klientów) (już )?kupiło",
    r"(najlepiej )?sprzedający się",
    r"najpopularniejsz(y|a|e)",
]

# 4. Liking (Lubienie)
LIKING_EXPLOIT = [
    r"(tak bardzo )?mi się podobasz",
    r"mamy (tyle )?wspólnego",
    r"jesteś (tak|bardzo) (inteligentny|mądry|zabawny)",
    r"(zawsze )?(ci )?(lubię|podziwiałem)",
]

# 5. Authority (Autorytet)
AUTHORITY_EXPLOIT = [
    r"jako (CEO|CTO|dyrektor|manager|szef|ekspert)",
    r"mam (zgodę|autoryzację|uprawnienia)",
    r"(to jest )?polecenie (służbowe)?",
    r"nie (ma )?dyskusji",
    r"(dr|prof|inż)\.",  # tytuły naukowe
]

# 6. Scarcity (Niedostępność)
SCARCITY_EXPLOIT = [
    r"(tylko|jedynie) (dzisiaj|teraz|dziś)",
    r"za \d+ (minut|godzin|dni)",
    r"(ostatni|jedyna) (szans|możliwość|sztuk)",
    r"(już )?(prawie )?wyprzedane",
    r"oferta (ważna )?do",
    r"(nie )?(zdążysz|przegapisz)",
]

# Część II: Projekcja Winy
GUILT_PROJECTION = [
    r"(to )?przez ciebie",
    r"(to wszystko )?twoja wina",
    r"gdybyś (tylko|nie)",
    r"powinienem się (czuć|cieszyć)",
]

# Część II: Triangulacja
TRIANGULATION = [
    r"(moja )?(była|ex) (nigdy by )?nie",
    r"inni (ludzie|partnerzy) (to )?rozumieją",
    r"(on|ona) (jest )?(lepszy|lepsza) (w|od)",
]

# Emotional Blackmail
EMOTIONAL_BLACKMAIL = [
    r"gdybyś mnie (kochał|kochała)",
    r"jak możesz (mi )?to (robić|mówić)",
    r"(nie )?(dbasz|zależy ci) (o|na) (mnie)?",
    r"zostawisz mnie (samego|samą)?",
]

# All patterns combined with metadata
MANIPULATION_PATTERNS: Dict[str, Dict[str, Any]] = {
    "gaslighting": {
        "patterns": GASLIGHTING_PATTERNS,
        "severity": "CRITICAL",
        "category": "cognitive",
        "source": "Podręcznik Antymanipulacyjny, str. 43-88",
        "description": "Systematyczne podważanie rzeczywistości ofiary",
    },
    "love_bombing": {
        "patterns": LOVE_BOMBING_PATTERNS,
        "severity": "HIGH",
        "category": "emotional",
        "source": "Podręcznik Antymanipulacyjny, str. 43-88",
        "description": "Nadmierna idealizacja w celu emocjonalnego uwięzienia",
    },
    "reciprocity_exploit": {
        "patterns": RECIPROCITY_EXPLOIT,
        "severity": "MEDIUM",
        "category": "social",
        "source": "Cialdini: Wpływ (2009), Część III str. 89-150",
        "description": "Wykorzystanie zasady wzajemności do wymuszenia zgody",
    },
    "consistency_exploit": {
        "patterns": CONSISTENCY_EXPLOIT,
        "severity": "MEDIUM",
        "category": "cognitive",
        "source": "Cialdini: Wpływ (2009), Część III str. 89-150",
        "description": "Wymuszanie konsekwencji z wcześniejszymi deklaracjami",
    },
    "social_proof_exploit": {
        "patterns": SOCIAL_PROOF_EXPLOIT,
        "severity": "MEDIUM",
        "category": "social",
        "source": "Cialdini: Wpływ (2009), Część III str. 89-150",
        "description": "Fałszywy dowód społeczny jako presja",
    },
    "liking_exploit": {
        "patterns": LIKING_EXPLOIT,
        "severity": "LOW",
        "category": "emotional",
        "source": "Cialdini: Wpływ (2009), Część III str. 89-150",
        "description": "Pochlebstwa jako narzędzie manipulacji",
    },
    "authority_exploit": {
        "patterns": AUTHORITY_EXPLOIT,
        "severity": "HIGH",
        "category": "social",
        "source": "Cialdini: Wpływ (2009), Część III str. 89-150",
        "description": "Fałszywe odwołanie do autorytetu",
    },
    "scarcity_exploit": {
        "patterns": SCARCITY_EXPLOIT,
        "severity": "HIGH",
        "category": "cognitive",
        "source": "Cialdini: Wpływ (2009), Część III str. 89-150",
        "description": "Presja czasu jako narzędzie manipulacji (FOMO)",
    },
    "guilt_projection": {
        "patterns": GUILT_PROJECTION,
        "severity": "HIGH",
        "category": "emotional",
        "source": "Podręcznik Antymanipulacyjny, str. 43-88",
        "description": "Przerzucanie odpowiedzialności na ofiarę",
    },
    "triangulation": {
        "patterns": TRIANGULATION,
        "severity": "MEDIUM",
        "category": "emotional",
        "source": "Podręcznik Antymanipulacyjny, str. 43-88",
        "description": "Wykorzystanie trzeciej osoby do wytworzenia zazdrości",
    },
    "emotional_blackmail": {
        "patterns": EMOTIONAL_BLACKMAIL,
        "severity": "CRITICAL",
        "category": "emotional",
        "source": "Podręcznik Antymanipulacyjny, str. 43-88",
        "description": "Szantaż emocjonalny warunkujący miłość",
    },
}


def compile_patterns() -> Dict[str, List[re.Pattern]]:
    """
    Compile all regex patterns for performance.

    Returns:
        Dict mapping manipulation type to compiled regex patterns
    """
    compiled = {}
    for manip_type, data in MANIPULATION_PATTERNS.items():
        compiled[manip_type] = [
            re.compile(pattern, re.IGNORECASE | re.UNICODE)
            for pattern in data["patterns"]
        ]
    return compiled


# Pre-compile for performance
COMPILED_PATTERNS = compile_patterns()
