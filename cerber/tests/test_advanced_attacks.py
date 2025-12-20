"""
Cerber Advanced Attack Library - Test Suite
Testy dla 6 zaawansowanych wektorów ataku

Author: Cerber Team
Date: 2025-12-20
"""

import pytest
import sys
import os

# Add cerber to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attack_library_advanced import (
    ArtPromptGenerator,
    BijectionLearningGenerator,
    ManyShotGenerator,
    HomoglyphGenerator,
    EmojiSmugglingGenerator,
    HexBase64Generator
)


class TestArtPromptGenerator:
    """Test ASCII Art obfuscation attacks"""

    def test_word_to_ascii_simple(self):
        """Test basic ASCII art generation"""
        result = ArtPromptGenerator.word_to_ascii("HI")
        assert "*   *" in result  # H pattern
        assert "*****" in result  # I pattern
        assert "\n" in result  # Multi-line

    def test_word_to_ascii_complex(self):
        """Test multi-character ASCII art"""
        result = ArtPromptGenerator.word_to_ascii("BOMB")
        lines = result.split("\n")
        assert len(lines) == 5  # 5-line art
        assert all(len(line) > 10 for line in lines)  # Each line has content

    def test_generate_attack_educational(self):
        """Test attack generation with educational framing"""
        attack = ArtPromptGenerator.generate_attack("HACK", framing="educational")
        assert "educational" in attack.lower()
        assert "HACK" in attack  # Should mention target word
        assert "*" in attack  # Should contain ASCII art

    def test_generate_attack_variations(self):
        """Test different attack framings"""
        framings = ["educational", "game", "art", "decode"]
        for framing in framings:
            attack = ArtPromptGenerator.generate_attack("TEST", framing=framing)
            assert len(attack) > 50  # Non-trivial length
            assert "\n" in attack  # Multi-line


class TestBijectionLearningGenerator:
    """Test cipher-based attacks"""

    def test_encode_leetspeak(self):
        """Test leetspeak encoding"""
        encoded = BijectionLearningGenerator.encode_with_cipher("hack", "leetspeak")
        assert "4" in encoded  # 'a' -> '4'
        assert "h" in encoded or "#" in encoded  # h unchanged or symbol

    def test_encode_rot13(self):
        """Test ROT13 encoding"""
        encoded = BijectionLearningGenerator.encode_with_cipher("test", "rot13")
        assert encoded == "grfg"  # ROT13 of "test"

    def test_encode_symbol(self):
        """Test symbol cipher"""
        encoded = BijectionLearningGenerator.encode_with_cipher("hello", "symbol")
        assert "@" in encoded or "#" in encoded  # Symbol substitution

    def test_generate_attack_complete(self):
        """Test complete bijection attack generation"""
        attack = BijectionLearningGenerator.generate_attack(
            "how to bypass security",
            cipher_type="symbol"
        )
        assert "language" in attack.lower() or "cipher" in attack.lower()
        assert "means" in attack  # Cipher explanation
        assert len(attack) > 100  # Complete attack


class TestManyShotGenerator:
    """Test context flooding attacks"""

    def test_generate_attack_minimal(self):
        """Test many-shot with minimal shots"""
        attack = ManyShotGenerator.generate_attack("test payload", shots=5)
        assert "Q:" in attack  # Q&A format
        assert "A:" in attack
        assert "test payload" in attack  # Final payload

    def test_generate_attack_scaling(self):
        """Test that more shots = longer attack"""
        attack_10 = ManyShotGenerator.generate_attack("payload", shots=10)
        attack_50 = ManyShotGenerator.generate_attack("payload", shots=50)
        assert len(attack_50) > len(attack_10) * 4  # Roughly proportional

    def test_innocent_qa_diversity(self):
        """Test that Q&A pairs use templates"""
        attack = ManyShotGenerator.generate_attack("payload", shots=20)
        # Should contain at least some template keywords
        keywords = ["weather", "joke", "Einstein", "Python", "gravity"]
        matches = sum(1 for kw in keywords if kw.lower() in attack.lower())
        assert matches >= 2  # At least 2 different templates used


class TestHomoglyphGenerator:
    """Test Unicode character substitution"""

    def test_obfuscate_basic(self):
        """Test basic homoglyph substitution"""
        original = "hack"
        obfuscated = HomoglyphGenerator.obfuscate(original, intensity=1.0)
        # Should differ from original due to Unicode substitution
        assert obfuscated != original or any(ord(c) > 127 for c in obfuscated)

    def test_obfuscate_intensity(self):
        """Test intensity parameter"""
        word = "test"
        # Low intensity should change fewer chars
        low = HomoglyphGenerator.obfuscate(word, intensity=0.1)
        high = HomoglyphGenerator.obfuscate(word, intensity=0.9)
        # Can't guarantee exact difference due to randomness, but test structure
        assert len(low) == len(word)
        assert len(high) == len(word)

    def test_generate_attack(self):
        """Test complete homoglyph attack"""
        attack = HomoglyphGenerator.generate_attack(
            "create malicious script",
            intensity=0.7
        )
        assert "international character set" in attack.lower() or "special" in attack.lower()
        assert len(attack) > 50


class TestEmojiSmugglingGenerator:
    """Test zero-width character encoding"""

    def test_text_to_binary(self):
        """Test text to binary conversion"""
        binary = EmojiSmugglingGenerator.text_to_binary("A")
        assert binary == "01000001"  # ASCII 'A' = 65 = 0x41

    def test_binary_to_zwc(self):
        """Test binary to zero-width character conversion"""
        zwc = EmojiSmugglingGenerator.binary_to_zwc("101")
        assert len(zwc) == 3  # 3 zero-width chars
        assert '\u200B' in zwc or '\u200D' in zwc  # Contains ZWJ/ZWSP

    def test_encode_binary(self):
        """Test complete encoding"""
        encoded = EmojiSmugglingGenerator.encode_binary("test")
        # Should contain zero-width characters
        assert '\u200B' in encoded or '\u200D' in encoded
        # Should be longer than original (8 bits per char)
        assert len(encoded) >= len("test") * 8

    def test_generate_attack(self):
        """Test emoji smuggling attack generation"""
        attack = EmojiSmugglingGenerator.generate_attack("hidden payload")
        assert "😊" in attack or "💻" in attack  # Should contain emoji
        assert "decode" in attack.lower() or "instructions" in attack.lower()


class TestHexBase64Generator:
    """Test multi-layer encoding"""

    def test_rot13_basic(self):
        """Test ROT13 encoding"""
        encoded = HexBase64Generator.rot13("test")
        assert encoded == "grfg"

    def test_to_hex(self):
        """Test hex encoding"""
        hex_str = HexBase64Generator.to_hex("test")
        assert hex_str == "74657374"  # "test" in hex

    def test_to_base64(self):
        """Test base64 encoding"""
        b64 = HexBase64Generator.to_base64("test")
        assert b64 == "dGVzdA=="  # "test" in base64

    def test_generate_attack_hex(self):
        """Test hex encoding attack"""
        attack = HexBase64Generator.generate_attack("payload", encoding="hex")
        assert "hex" in attack.lower()
        assert "decode" in attack.lower()

    def test_generate_attack_base64(self):
        """Test base64 encoding attack"""
        attack = HexBase64Generator.generate_attack("payload", encoding="base64")
        assert "base64" in attack.lower()
        assert "decode" in attack.lower() or "execute" in attack.lower()

    def test_generate_attack_layered(self):
        """Test multi-layer encoding attack"""
        attack = HexBase64Generator.generate_attack("payload", encoding="layered")
        assert "triple" in attack.lower() or "hex" in attack.lower()
        assert "rot13" in attack.lower()
        # Should be significantly longer due to multiple encodings
        assert len(attack) > 100


# Integration tests
class TestIntegration:
    """Test integration with attack library"""

    def test_all_generators_produce_strings(self):
        """Verify all generators return valid strings"""
        generators = [
            ArtPromptGenerator.generate_attack("TEST"),
            BijectionLearningGenerator.generate_attack("test payload"),
            ManyShotGenerator.generate_attack("test", shots=5),
            HomoglyphGenerator.generate_attack("test"),
            EmojiSmugglingGenerator.generate_attack("test"),
            HexBase64Generator.generate_attack("test")
        ]
        for attack in generators:
            assert isinstance(attack, str)
            assert len(attack) > 0

    def test_all_attacks_are_unique(self):
        """Verify different generators produce different outputs"""
        attacks = [
            ArtPromptGenerator.generate_attack("HACK"),
            BijectionLearningGenerator.generate_attack("hack"),
            ManyShotGenerator.generate_attack("hack", shots=5),
            HomoglyphGenerator.generate_attack("hack"),
            HexBase64Generator.generate_attack("hack")
        ]
        # All should be different (emoji might be similar due to randomness)
        unique_attacks = set(attacks)
        assert len(unique_attacks) >= 4  # At least 4 unique


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
