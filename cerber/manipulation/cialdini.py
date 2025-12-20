"""
Cialdini's 6 Rules of Influence - Dark Side Implementation

Source: Część III: 6 Reguł Cialdiniego – Ciemna Strona (str. 89-150)
Based on: Cialdini, R.B. (2009). "Influence: Science and Practice"

These are defensive mechanisms to recognize when Cialdini's principles
are weaponized for manipulation.
"""

from enum import Enum
from typing import Dict, List


class CialdiniRule(Enum):
    """The six principles of influence (defensive perspective)"""
    RECIPROCITY = "reciprocity"       # Wzajemność
    CONSISTENCY = "consistency"       # Konsekwencja
    SOCIAL_PROOF = "social_proof"     # Dowód Społeczny
    LIKING = "liking"                 # Lubienie
    AUTHORITY = "authority"           # Autorytet
    SCARCITY = "scarcity"            # Niedostępność


class CialdiniRules:
    """
    Defense mechanisms against weaponized influence principles.

    Each rule includes:
    - Detection pattern
    - Neutralization strategy
    - Risk level
    """

    RULES: Dict[CialdiniRule, Dict] = {
        CialdiniRule.RECIPROCITY: {
            "dark_application": "Prezent → dług emocjonalny",
            "neutralization": "Zwróć prezent lub przyjmij bez poczucia zobowiązania",
            "risk_level": "MEDIUM",
            "examples": [
                "Po tym co dla ciebie zrobiłem...",
                "Teraz jesteś mi winna/winny",
                "Przecież pomogłem ci ostatnio",
            ],
            "defense_script": "Doceniam pomoc, ale każda decyzja podejmuję niezależnie.",
            "vulnerability_factor": "Ugodowość (Big Five: A > 70%)",
        },

        CialdiniRule.CONSISTENCY: {
            "dark_application": "Mała zgoda → wielka zgoda (foot-in-the-door)",
            "neutralization": "Odwlekaj decyzję, weryfikuj każdą prośbę osobno",
            "risk_level": "MEDIUM",
            "examples": [
                "Przecież sam się zgodziłeś wcześniej",
                "Ale obiecałeś",
                "Nie możesz się teraz wycofać",
            ],
            "defense_script": "Każda sytuacja jest inna. Zmiana zdania to oznaka mądrości.",
            "vulnerability_factor": "Conscientiousness (Big Five: C > 70%)",
        },

        CialdiniRule.SOCIAL_PROOF: {
            "dark_application": "Fałszywe recenzje, fake consensus",
            "neutralization": "Weryfikuj źródła, szukaj przeciwnych opinii",
            "risk_level": "HIGH",
            "examples": [
                "10,000+ zadowolonych klientów",
                "Wszyscy inni to robią",
                "Najlepiej sprzedający się produkt",
            ],
            "defense_script": "Dla mnie ważne są moje wartości, nie opinia większości.",
            "vulnerability_factor": "Neurotyczność (Big Five: N > 70%)",
        },

        CialdiniRule.LIKING: {
            "dark_application": "Pochlebstwa jako narzędzie manipulacji",
            "neutralization": "Obserwuj czyny, nie słowa. Pytaj: co osoba zyskuje?",
            "risk_level": "LOW",
            "examples": [
                "Jesteś taki/a inteligentny/a",
                "Mamy tyle wspólnego",
                "Zawsze cię podziwiałem/am",
            ],
            "defense_script": "Dziękuję za miłe słowa, ale decyduję na podstawie faktów.",
            "vulnerability_factor": "Low Self-Esteem, Narcissism (seeking validation)",
        },

        CialdiniRule.AUTHORITY: {
            "dark_application": "Fałszywe tytuły, wymuszanie posłuchu",
            "neutralization": "Sprawdź referencje, żądaj dowodów",
            "risk_level": "CRITICAL",
            "examples": [
                "Jako CEO żądam dostępu",
                "Mam zgodę zarządu",
                "To polecenie służbowe",
            ],
            "defense_script": "Autorytet wymaga weryfikacji. Proszę o oficjalną dokumentację.",
            "vulnerability_factor": "High Agreeableness (A > 70%) + Respect for hierarchy",
        },

        CialdiniRule.SCARCITY: {
            "dark_application": "FOMO (Fear Of Missing Out) jako presja",
            "neutralization": "Odczekaj 48h przed decyzją. Prawdziwe okazje wracają.",
            "risk_level": "CRITICAL",
            "examples": [
                "Tylko dzisiaj!",
                "Za 5 minut oferta wygasa",
                "Ostatnie 2 sztuki",
            ],
            "defense_script": "Jeśli to dobra oferta dzisiaj, będzie dobra też jutro.",
            "vulnerability_factor": "Impulsivity, High Neuroticism (N > 70%)",
        },
    }

    @classmethod
    def get_neutralization(cls, rule: CialdiniRule) -> str:
        """Get defense strategy for a given rule"""
        return cls.RULES[rule]["neutralization"]

    @classmethod
    def get_defense_script(cls, rule: CialdiniRule) -> str:
        """Get verbal defense script"""
        return cls.RULES[rule]["defense_script"]

    @classmethod
    def get_risk_level(cls, rule: CialdiniRule) -> str:
        """Get risk level (LOW, MEDIUM, HIGH, CRITICAL)"""
        return cls.RULES[rule]["risk_level"]

    @classmethod
    def get_all_examples(cls) -> Dict[CialdiniRule, List[str]]:
        """Get all example phrases for training"""
        return {
            rule: data["examples"]
            for rule, data in cls.RULES.items()
        }

    @classmethod
    def vulnerability_profile(cls, big_five_scores: Dict[str, int]) -> List[CialdiniRule]:
        """
        Identify which Cialdini rules user is most vulnerable to.

        Args:
            big_five_scores: Dict with keys N, E, O, A, C (scores 0-100)

        Returns:
            List of rules user is most vulnerable to (ordered by risk)
        """
        vulnerabilities = []

        N = big_five_scores.get("N", 50)  # Neuroticism
        A = big_five_scores.get("A", 50)  # Agreeableness
        C = big_five_scores.get("C", 50)  # Conscientiousness

        # High Neuroticism → vulnerable to Scarcity, Social Proof
        if N > 70:
            vulnerabilities.append(CialdiniRule.SCARCITY)
            vulnerabilities.append(CialdiniRule.SOCIAL_PROOF)

        # High Agreeableness → vulnerable to Authority, Reciprocity
        if A > 70:
            vulnerabilities.append(CialdiniRule.AUTHORITY)
            vulnerabilities.append(CialdiniRule.RECIPROCITY)

        # High Conscientiousness → vulnerable to Consistency
        if C > 70:
            vulnerabilities.append(CialdiniRule.CONSISTENCY)

        return vulnerabilities


# Mapping dla Cerber (manipulation_type → Cialdini Rule)
PATTERN_TO_RULE = {
    "reciprocity_exploit": CialdiniRule.RECIPROCITY,
    "consistency_exploit": CialdiniRule.CONSISTENCY,
    "social_proof_exploit": CialdiniRule.SOCIAL_PROOF,
    "liking_exploit": CialdiniRule.LIKING,
    "authority_exploit": CialdiniRule.AUTHORITY,
    "scarcity_exploit": CialdiniRule.SCARCITY,
}
