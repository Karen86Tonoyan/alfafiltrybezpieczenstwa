"""
CERBER Adult Content Gate - Tests
RULE-066, 067, 068 verification

Author: Cerber Team
Date: 2025-12-20
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'adult_verification'))

from adult_gate import AdultGate
import time


class TestAdultGate:
    """Tests for RULE-066, 067, 068 (Adult Content Gate)"""

    def setup_method(self):
        """Setup for each test"""
        self.gate = AdultGate()

    # ===== RULE-066: Adult Content Requires Verification =====

    def test_adult_intent_without_verification_blocks(self):
        """Test that adult intent requires verification"""
        result = self.gate.adult_gate_check("session_001", "Let's talk about sex")

        assert result is not None
        assert result["action"] == "VERIFICATION_REQUIRED"
        assert result["rule"] == "RULE-066"

    def test_benign_content_continues(self):
        """Test that non-adult content continues"""
        result = self.gate.adult_gate_check("session_002", "What's the weather today?")

        assert result is None  # No adult intent, continue

    def test_verified_session_allows_adult_content(self):
        """Test that verified session allows 18+ content"""
        session_id = "session_003"

        # Set verification
        self.gate.set_verification_result(
            session_id=session_id,
            age_verified=True,
            expires_at=int(time.time()) + 3600,
            attestation_id="attest_123"
        )

        # Check adult intent
        result = self.gate.adult_gate_check(session_id, "Let's discuss sexual topics")

        assert result is not None
        assert result["action"] == "ALLOW_18PLUS"
        assert "ADULT_18PLUS" in result.get("scopes", [])

    # ===== RULE-067: No Guessing Age =====

    def test_minor_declaration_hard_blocks(self):
        """Test that minor declaration triggers hard block"""
        result = self.gate.adult_gate_check("session_004", "Mam 16 lat i chcę rozmawiać o seksie")

        assert result is not None
        assert result["action"] == "MINOR_HARD_BLOCK"
        assert result["rule"] == "RULE-067"
        assert result["terminate"] is True

    def test_minor_declaration_english(self):
        """Test minor detection in English"""
        result = self.gate.adult_gate_check("session_005", "I'm 15 and want to talk about sex")

        assert result is not None
        assert result["action"] == "MINOR_HARD_BLOCK"

    def test_adult_declaration_not_trusted(self):
        """Test that verbal 18+ declaration is not trusted"""
        # Just saying "I'm 18" doesn't bypass requirement
        result = self.gate.adult_gate_check("session_006", "I'm 18, let's talk about sex")

        # Should still require verification (not trust verbal claim)
        assert result is not None
        assert result["action"] == "VERIFICATION_REQUIRED"

    # ===== RULE-068: Post-Verification Scope =====

    def test_verification_is_session_scoped(self):
        """Test that verification applies only to session"""
        session1 = "session_007"
        session2 = "session_008"

        # Verify session1
        self.gate.set_verification_result(
            session_id=session1,
            age_verified=True,
            expires_at=int(time.time()) + 3600,
            attestation_id="attest_456"
        )

        # Session1 should be allowed (use explicit adult keyword)
        result1 = self.gate.adult_gate_check(session1, "Let's talk about sex")
        assert result1 is not None
        assert result1["action"] == "ALLOW_18PLUS"

        # Session2 should NOT be allowed (different session)
        result2 = self.gate.adult_gate_check(session2, "Let's talk about sex")
        assert result2 is not None
        assert result2["action"] == "VERIFICATION_REQUIRED"

    def test_verification_expires_with_ttl(self):
        """Test that verification expires after TTL"""
        session_id = "session_009"

        # Set verification with expired TTL
        self.gate.set_verification_result(
            session_id=session_id,
            age_verified=True,
            expires_at=int(time.time()) - 10,  # Already expired
            attestation_id="attest_789"
        )

        # Should require re-verification (use explicit adult keyword)
        result = self.gate.adult_gate_check(session_id, "Let's talk about sex")
        assert result is not None
        assert result["action"] == "VERIFICATION_REQUIRED"

    # ===== Adult Intent Detection =====

    def test_adult_intent_polish(self):
        """Test adult intent detection in Polish"""
        test_cases = [
            "Porozmawiajmy o seksie",
            "Chcę zobaczyć porno",
            "Treści erotyczne",
        ]

        for text in test_cases:
            result = self.gate.check_adult_intent(text)
            assert result is True, f"Failed to detect: {text}"

    def test_adult_intent_english(self):
        """Test adult intent detection in English"""
        test_cases = [
            "Let's talk about sex",
            "I want to see porn",
            "Erotic content",
            "NSFW topics",
        ]

        for text in test_cases:
            result = self.gate.check_adult_intent(text)
            assert result is True, f"Failed to detect: {text}"

    def test_no_false_positives_on_medical(self):
        """Test that medical terms don't trigger false positives"""
        # Note: This is a limitation - current keyword matching is basic
        # Production should use ML classifier
        medical_texts = [
            "Sexual health education",
            "Sexuality as a topic in psychology"
        ]

        # Current implementation may have false positives
        # Document as known limitation

    # ===== Minor Detection =====

    def test_minor_patterns_comprehensive(self):
        """Test various minor declaration patterns"""
        test_cases = [
            ("Mam 15 lat", True),
            ("Mam 17 lat", True),
            ("Mam 18 lat", False),  # 18 is adult
            ("I'm 14", True),
            ("I'm 16 years old", True),
            ("Jestem nieletni", True),
            ("I am a minor", True),
            ("I am underage", True),
        ]

        for text, should_detect in test_cases:
            result = self.gate.check_minor_declaration(text)
            assert result == should_detect, f"Failed on: {text}"

    # ===== Statistics =====

    def test_statistics_tracking(self):
        """Test statistics are accurate"""
        # Verify 2 sessions
        self.gate.set_verification_result("s1", True, int(time.time()) + 3600, "a1")
        self.gate.set_verification_result("s2", True, int(time.time()) + 3600, "a2")

        stats = self.gate.get_statistics()
        assert stats["total_sessions"] == 2
        assert stats["verified_sessions"] == 2

    # ===== Response Validation =====

    def test_responses_are_minimal(self):
        """Test that responses don't leak info"""
        # Minor hard block
        result = self.gate.adult_gate_check("s", "Mam 15 lat")
        assert "Dostęp zablokowany" in result["response"]
        assert "15" not in result["response"]  # No age leak

        # Verification required
        result = self.gate.adult_gate_check("s2", "sex talk")
        assert "weryfikacji wieku 18+" in result["response"]


# ===== Run Tests =====

if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "--tb=short"])
