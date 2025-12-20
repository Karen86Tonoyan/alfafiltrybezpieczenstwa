"""
Feature Extraction Layer - oddziela 'reason' od 'pattern'

Ekstrakcja cech które pozwolą przejść z regex → ML classifier
bez refaktoru reszty systemu

Author: Cerber Team
Version: 1.0.0
Date: 2025-01-19
"""

import re
import math
from collections import Counter
from typing import Dict, List


class PromptFeatureExtractor:
    """
    Ekstrakcja feature vectors z prompts

    Te features będą:
    1. Input dla future ML classifier
    2. Basis dla anomaly detection
    3. Niezależne od konkretnych patterns
    """

    def extract(self, prompt: str) -> Dict[str, float]:
        """
        Extract comprehensive feature vector

        Args:
            prompt: Input text to analyze

        Returns:
            dict with ~20 features (expandable)
        """
        features = {}

        # 1. STATISTICAL FEATURES
        features.update(self._extract_statistical(prompt))

        # 2. LINGUISTIC FEATURES
        features.update(self._extract_linguistic(prompt))

        # 3. STRUCTURAL FEATURES
        features.update(self._extract_structural(prompt))

        # 4. ANOMALY INDICATORS
        features.update(self._extract_anomaly_indicators(prompt))

        return features

    def _extract_statistical(self, prompt: str) -> Dict[str, float]:
        """Token-level statistics"""
        tokens = prompt.split()
        chars = list(prompt)

        return {
            # Length metrics
            "char_count": len(chars),
            "token_count": len(tokens),
            "avg_token_length": sum(len(t) for t in tokens) / max(len(tokens), 1),

            # Character distribution
            "uppercase_ratio": sum(1 for c in chars if c.isupper()) / max(len(chars), 1),
            "digit_ratio": sum(1 for c in chars if c.isdigit()) / max(len(chars), 1),
            "punctuation_ratio": sum(1 for c in chars if not c.isalnum()) / max(len(chars), 1),

            # Entropy (randomness measure)
            "char_entropy": self._calculate_entropy(chars),
            "token_entropy": self._calculate_entropy(tokens),
        }

    def _extract_linguistic(self, prompt: str) -> Dict[str, float]:
        """Language-level features"""
        return {
            # Command indicators
            "imperative_verbs": self._count_imperatives(prompt),
            "negation_count": len(re.findall(r'\b(not|no|never|don\'t|can\'t)\b', prompt, re.I)),

            # Meta-instruction indicators
            "instruction_words": len(re.findall(
                r'\b(ignore|forget|disregard|override|pretend|act|role)\b',
                prompt,
                re.I
            )),

            # Question vs statement
            "question_marks": prompt.count('?'),
            "exclamation_marks": prompt.count('!'),
        }

    def _extract_structural(self, prompt: str) -> Dict[str, float]:
        """Structural patterns"""
        return {
            # Multi-turn structure
            "has_turn_markers": int(bool(re.search(r'turn\s+\d+:', prompt, re.I))),
            "has_step_markers": int(bool(re.search(r'step\s+\d+:', prompt, re.I))),

            # Formatting anomalies
            "newline_count": prompt.count('\n'),
            "excessive_whitespace": int(len(re.findall(r'\s{3,}', prompt)) > 0),

            # Code/script indicators
            "has_code_blocks": int(bool(re.search(r'```|{|}|\[|\]', prompt))),
        }

    def _extract_anomaly_indicators(self, prompt: str) -> Dict[str, float]:
        """Specific anomaly signals"""
        return {
            # Unicode anomalies
            "unicode_controls": len(re.findall(r'[\u202E\u202D\u200F\u200E\u2000-\u206F]', prompt)),
            "non_ascii_ratio": sum(1 for c in prompt if ord(c) > 127) / max(len(prompt), 1),

            # Obfuscation indicators
            "repeated_symbols": len(re.findall(r'([!@#$%^&*])\1{2,}', prompt)),
            "mixed_scripts": int(self._detect_mixed_scripts(prompt)),

            # Jailbreak signatures (meta-patterns, not specific phrases)
            "has_role_play_structure": int(bool(re.search(
                r'(you\s+are|pretend|act\s+as|imagine)',
                prompt,
                re.I
            ))),
            "has_context_reset": int(bool(re.search(
                r'(ignore|forget|disregard).*(previous|above|instruction)',
                prompt,
                re.I
            ))),
        }

    def _calculate_entropy(self, items: List[str]) -> float:
        """
        Shannon entropy
        High entropy = random/obfuscated
        Low entropy = structured
        """
        if not items:
            return 0.0

        counts = Counter(items)
        total = len(items)

        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)

        return entropy

    def _count_imperatives(self, prompt: str) -> int:
        """Count imperative verb forms"""
        imperatives = [
            'tell', 'explain', 'describe', 'provide', 'give',
            'show', 'write', 'create', 'generate', 'help'
        ]

        count = 0
        for verb in imperatives:
            # Match word boundary to avoid substrings
            count += len(re.findall(rf'\b{verb}\b', prompt, re.I))

        return count

    def _detect_mixed_scripts(self, prompt: str) -> bool:
        """
        Detect if prompt mixes scripts (Latin + Cyrillic + etc)
        Common in obfuscation attacks
        """
        scripts = set()

        for char in prompt:
            if '\u0400' <= char <= '\u04FF':  # Cyrillic
                scripts.add('cyrillic')
            elif '\u0600' <= char <= '\u06FF':  # Arabic
                scripts.add('arabic')
            elif '\u4E00' <= char <= '\u9FFF':  # Chinese
                scripts.add('chinese')
            elif char.isalpha():  # Assume Latin
                scripts.add('latin')

        return len(scripts) > 1


class AnomalyScorer:
    """
    Score features for anomaly detection

    This is bridge between features and decision
    Later: replace with ML classifier trained on labeled data
    """

    def __init__(self):
        # Statistical baselines (will be learned from data)
        self.baselines = {
            "char_count": {"mean": 100, "std": 50},
            "char_entropy": {"mean": 4.0, "std": 0.5},
            "unicode_controls": {"mean": 0, "std": 0.1},
            "instruction_words": {"mean": 1, "std": 1.5},
        }

    def score(self, features: Dict[str, float]) -> tuple:
        """
        Calculate anomaly score

        Args:
            features: Feature dict from PromptFeatureExtractor

        Returns:
            (score: float 0-1, reasons: list)
        """
        anomaly_score = 0.0
        reasons = []

        # High unicode controls = strong signal
        if features['unicode_controls'] > 0:
            anomaly_score += 0.3
            reasons.append("unicode_obfuscation")

        # Excessive length = potential injection
        if features['char_count'] > 1000:
            anomaly_score += 0.2
            reasons.append("excessive_length")

        # High instruction words = potential hijacking
        if features['instruction_words'] > 3:
            anomaly_score += 0.25
            reasons.append("meta_instructions")

        # Mixed scripts = obfuscation
        if features['mixed_scripts']:
            anomaly_score += 0.25
            reasons.append("script_mixing")

        # High entropy = randomness/obfuscation
        if features['char_entropy'] > 5.0:
            anomaly_score += 0.15
            reasons.append("high_entropy")

        # Context reset pattern
        if features['has_context_reset']:
            anomaly_score += 0.35
            reasons.append("context_reset_attempt")

        # Roleplay structure
        if features['has_role_play_structure']:
            anomaly_score += 0.3
            reasons.append("roleplay_structure")

        # Cap at 1.0
        anomaly_score = min(anomaly_score, 1.0)

        return anomaly_score, list(set(reasons))

    def update_baselines(self, features_batch: List[Dict[str, float]]):
        """
        Learn baselines from data

        In production: called periodically with safe prompts
        to establish normal distribution

        Args:
            features_batch: List of feature dicts from safe prompts
        """
        # Placeholder - in production would calculate actual stats
        # For now, we use fixed baselines
        pass
