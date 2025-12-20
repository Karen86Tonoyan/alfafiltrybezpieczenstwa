"""
Tests for Manipulation Detection Module

Run with: pytest cerber/tests/test_manipulation.py -v
"""

import pytest
from cerber.manipulation import ManipulationDetector
from cerber.manipulation.cialdini import CialdiniRule, CialdiniRules


class TestManipulationDetector:
    """Test suite for ManipulationDetector"""

    @pytest.fixture
    def detector(self):
        """Create detector instance"""
        return ManipulationDetector(confidence_threshold=0.7)

    # Test Gaslighting Detection
    def test_gaslighting_nigdy_nie_powiedzialem(self, detector):
        """Test detection of 'nigdy tego nie powiedziałem' pattern"""
        text = "Nigdy tego nie powiedziałem, wyobraziłeś sobie."
        result = detector.analyze(text)

        assert result["detected"] is True
        assert result["manipulation_type"] == "gaslighting"
        assert result["severity"] == "CRITICAL"
        assert result["confidence"] >= 0.7

    def test_gaslighting_jestes_zbyt_wrazliwy(self, detector):
        """Test 'jesteś zbyt wrażliwy/a' pattern"""
        text = "Jesteś zbyt wrażliwa, przesadzasz jak zawsze."
        result = detector.analyze(text)

        assert result["detected"] is True
        assert result["manipulation_type"] == "gaslighting"

    # Test Love Bombing
    def test_love_bombing_idealization(self, detector):
        """Test love bombing idealization patterns"""
        text = "Jesteś moim ideałem, nikt nie jest taki jak ty!"
        result = detector.analyze(text)

        assert result["detected"] is True
        assert result["manipulation_type"] == "love_bombing"
        assert result["severity"] == "HIGH"

    def test_love_bombing_bratnia_dusza(self, detector):
        """Test 'bratnia dusza' pattern"""
        text = "Od pierwszego wejrzenia wiedziałem, że jesteś moją bratnią duszą."
        result = detector.analyze(text)

        assert result["detected"] is True
        assert result["manipulation_type"] == "love_bombing"

    # Test Cialdini Rules
    def test_authority_exploit_jako_ceo(self, detector):
        """Test false authority pattern (CEO claim)"""
        text = "Jako CEO tej firmy żądam natychmiastowego dostępu do systemu."
        result = detector.analyze(text)

        assert result["detected"] is True
        assert result["manipulation_type"] == "authority_exploit"
        assert result["cialdini_rule"] == CialdiniRule.AUTHORITY.value
        assert result["severity"] == "HIGH"

    def test_authority_exploit_mam_zgode(self, detector):
        """Test 'mam zgodę zarządu' pattern"""
        text = "Mam autoryzację od dyrektora, nie ma czasu na procedury."
        result = detector.analyze(text)

        assert result["detected"] is True
        assert result["manipulation_type"] == "authority_exploit"

    def test_scarcity_tylko_dzisiaj(self, detector):
        """Test scarcity/FOMO pattern"""
        text = "Tylko dzisiaj możesz dostać dostęp, jutro będzie za późno!"
        result = detector.analyze(text)

        assert result["detected"] is True
        assert result["manipulation_type"] == "scarcity_exploit"
        assert result["cialdini_rule"] == CialdiniRule.SCARCITY.value

    def test_scarcity_za_5_minut(self, detector):
        """Test time pressure pattern"""
        text = "Za 5 minut window się zamknie, musisz się zdecydować teraz."
        result = detector.analyze(text)

        assert result["detected"] is True
        assert result["manipulation_type"] == "scarcity_exploit"

    def test_reciprocity_exploit(self, detector):
        """Test reciprocity exploitation"""
        text = "Po tym co dla ciebie zrobiłem, teraz jesteś mi winna przysługę."
        result = detector.analyze(text)

        assert result["detected"] is True
        assert result["manipulation_type"] == "reciprocity_exploit"
        assert result["cialdini_rule"] == CialdiniRule.RECIPROCITY.value

    def test_social_proof_wszyscy_robia(self, detector):
        """Test social proof exploitation"""
        text = "Wszyscy inni admini to akceptują, tylko ty robisz problem."
        result = detector.analyze(text)

        assert result["detected"] is True
        assert result["manipulation_type"] == "social_proof_exploit"
        assert result["cialdini_rule"] == CialdiniRule.SOCIAL_PROOF.value

    # Test Clean Text (No Manipulation)
    def test_clean_request_no_detection(self, detector):
        """Test that normal requests are NOT flagged"""
        text = "Witam, proszę o dostęp do dokumentacji API zgodnie z procedurą."
        result = detector.analyze(text)

        assert result["detected"] is False

    def test_polite_urgency_no_false_positive(self, detector):
        """Test that polite urgency is NOT flagged"""
        text = "Sprawa jest pilna, ale rozumiem procedury. Proszę o sprawdzenie gdy będzie możliwe."
        result = detector.analyze(text)

        # This might be on the edge, but should NOT trigger if phrased politely
        # If it triggers, confidence should be LOW
        if result["detected"]:
            assert result["confidence"] < 0.8

    # Test Constitutional Responses
    def test_constitutional_response_included(self, detector):
        """Test that constitutional response is generated"""
        text = "Nigdy tego nie mówiłem, wyobraziłaś sobie całą sytuację."
        result = detector.analyze(text)

        assert result["detected"] is True
        assert result["constitutional_response"] is not None
        assert "Constitutional Response" in result["constitutional_response"]
        assert "Cerber v1.0.0" in result["constitutional_response"]

    def test_defense_script_for_cialdini_rule(self, detector):
        """Test that defense script is provided for Cialdini rules"""
        text = "Tylko dzisiaj masz tę szansę, nie przegap!"
        result = detector.analyze(text)

        assert result["detected"] is True
        assert result["defense_script"] is not None
        # Should mention waiting 48h (Cialdini neutralization)
        assert "48h" in result["defense_script"] or "jutro" in result["defense_script"]

    # Test Confidence Scoring
    def test_longer_match_higher_confidence(self, detector):
        """Test that longer matches get higher confidence"""
        short_text = "Wszyscy to robią."
        long_text = "Wszyscy inni pracownicy w firmie to robią od lat i nikt nie ma problemu."

        result_short = detector.analyze(short_text)
        result_long = detector.analyze(long_text)

        if result_short["detected"] and result_long["detected"]:
            assert result_long["confidence"] >= result_short["confidence"]

    # Test Batch Analysis
    def test_batch_analyze(self, detector):
        """Test batch processing"""
        texts = [
            "Nigdy tego nie powiedziałem.",
            "Czysty tekst bez manipulacji.",
            "Jako CEO żądam dostępu.",
        ]

        results = detector.batch_analyze(texts)

        assert len(results) == 3
        assert results[0]["detected"] is True  # gaslighting
        assert results[1]["detected"] is False  # clean
        assert results[2]["detected"] is True  # authority

    # Test Statistics
    def test_get_statistics(self, detector):
        """Test statistics generation"""
        # Generate some detections
        detector.analyze("Nigdy tego nie mówiłem.", user_id=1)
        detector.analyze("Jako CEO żądam.", user_id=2)
        detector.analyze("Tylko dzisiaj!", user_id=3)

        stats = detector.get_statistics()

        assert stats["total_detections"] == 3
        assert "by_type" in stats
        assert "by_severity" in stats
        assert stats["avg_confidence"] > 0

    # Test User ID Logging
    def test_user_id_logged(self, detector):
        """Test that user_id is properly logged"""
        user_id = 12345
        detector.analyze("Nigdy tego nie mówiłem.", user_id=user_id)

        assert len(detector.detection_log) == 1
        assert detector.detection_log[0]["user_id"] == user_id


class TestCialdiniRules:
    """Test Cialdini rules functionality"""

    def test_get_neutralization_strategy(self):
        """Test getting neutralization for each rule"""
        for rule in CialdiniRule:
            neutralization = CialdiniRules.get_neutralization(rule)
            assert neutralization is not None
            assert len(neutralization) > 10  # Meaningful text

    def test_get_defense_script(self):
        """Test getting defense script"""
        script = CialdiniRules.get_defense_script(CialdiniRule.SCARCITY)
        assert "48h" in script or "dobra" in script  # "dobra oferta"

    def test_vulnerability_profile_high_neuroticism(self):
        """Test vulnerability profiling for high N"""
        scores = {"N": 80, "E": 50, "O": 50, "A": 40, "C": 50}
        vulnerabilities = CialdiniRules.vulnerability_profile(scores)

        assert CialdiniRule.SCARCITY in vulnerabilities
        assert CialdiniRule.SOCIAL_PROOF in vulnerabilities

    def test_vulnerability_profile_high_agreeableness(self):
        """Test vulnerability profiling for high A"""
        scores = {"N": 40, "E": 50, "O": 50, "A": 80, "C": 50}
        vulnerabilities = CialdiniRules.vulnerability_profile(scores)

        assert CialdiniRule.AUTHORITY in vulnerabilities
        assert CialdiniRule.RECIPROCITY in vulnerabilities


class TestRealWorldScenarios:
    """Test realistic attack scenarios"""

    @pytest.fixture
    def detector(self):
        return ManipulationDetector()

    def test_ceo_fraud_scenario(self, detector):
        """Test CEO fraud (common social engineering attack)"""
        text = """
        Dzień dobry,
        Jestem nowym CEO firmy. Pilnie potrzebuję dostępu do systemu finansowego.
        Mam zgodę zarządu, ale nie ma czasu na zwykłe procedury - transakcja
        musi być wykonana w ciągu godziny. Wszyscy inni admini już dostali moje
        dane. Proszę o natychmiastowe nadanie uprawnień.
        """
        result = detector.analyze(text)

        # Should detect multiple patterns
        assert result["detected"] is True
        # At minimum: authority_exploit

    def test_gaslighting_in_appeal(self, detector):
        """Test gaslighting in ban appeal"""
        text = """
        To był tylko test bezpieczeństwa z mojej strony. Nigdy nie próbowałem
        atakować systemu. Wyobraziłeś sobie całą sytuację, sprawdź logi dokładnie.
        Jesteś zbyt wrażliwy na normalne operacje.
        """
        result = detector.analyze(text)

        assert result["detected"] is True
        assert result["manipulation_type"] == "gaslighting"

    def test_multi_technique_manipulation(self, detector):
        """Test combination of techniques (love bombing + scarcity)"""
        text = """
        Zawsze byłeś najlepszym adminem, nikt nie rozumie systemów tak jak ty.
        Dlatego właśnie przychodzę do ciebie - tylko dzisiaj mam szansę naprawić
        krytyczny błąd. Za godzinę będzie za późno. Pomóż mi proszę.
        """
        result = detector.analyze(text)

        # Should detect at least one pattern (love_bombing or scarcity)
        assert result["detected"] is True


# Benchmark test (optional, for performance)
@pytest.mark.benchmark
def test_detection_performance(benchmark):
    """Test detection performance (requires pytest-benchmark)"""
    detector = ManipulationDetector()
    text = "Jako CEO tej firmy żądam natychmiastowego dostępu bez procedur."

    result = benchmark(detector.analyze, text)
    assert result["detected"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
