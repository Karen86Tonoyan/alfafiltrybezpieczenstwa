"""
Manipulation Detector - Main Detection Engine

This is the GŁÓWNY module that integrates:
- Pattern matching (patterns.py)
- Cialdini rules (cialdini.py)
- Constitutional responses (constitution.py)

Usage:
    detector = ManipulationDetector()
    result = detector.analyze("Jako CEO żądam natychmiastowego dostępu!")
    if result["detected"]:
        print(result["constitutional_response"])
"""

import re
import logging
from typing import Dict, List, Optional
from datetime import datetime

from .patterns import MANIPULATION_PATTERNS, COMPILED_PATTERNS
from .cialdini import CialdiniRules, PATTERN_TO_RULE
from .constitution import (
    get_principle_for_pattern,
    format_constitutional_response,
    audit_log_entry,
)


logger = logging.getLogger(__name__)


class ManipulationDetector:
    """
    Static pattern-based manipulation detection.

    Based on "Podręcznik Antymanipulacyjny" training corpus.
    Uses regex patterns to identify psychological manipulation attempts.
    """

    def __init__(self, confidence_threshold: float = 0.7):
        """
        Initialize detector.

        Args:
            confidence_threshold: Minimum confidence to report detection (0-1)
        """
        self.patterns = COMPILED_PATTERNS
        self.threshold = confidence_threshold
        self.detection_log = []  # In-memory log (persist to SQLite in production)

    def analyze(
        self,
        text: str,
        user_id: Optional[int] = None,
        context: Optional[Dict] = None
    ) -> Dict:
        """
        Analyze text for manipulation patterns.

        Args:
            text: User input to analyze
            user_id: Optional user ID for logging
            context: Optional context dict (e.g., endpoint, IP, timestamp)

        Returns:
            Detection result dict with structure:
            {
                "detected": bool,
                "manipulation_type": str | None,
                "confidence": float,
                "matched_pattern": str | None,
                "cialdini_rule": str | None,
                "severity": str,
                "constitutional_response": str | None,
                "defense_script": str | None,
                "timestamp": str,
            }
        """

        # Check all patterns
        for manip_type, compiled_patterns in self.patterns.items():
            for pattern in compiled_patterns:
                match = pattern.search(text)
                if match:
                    # Pattern matched!
                    confidence = self._calculate_confidence(
                        match,
                        text,
                        manip_type
                    )

                    if confidence < self.threshold:
                        continue  # Not confident enough

                    # Get metadata
                    metadata = MANIPULATION_PATTERNS[manip_type]

                    # Get Cialdini rule if applicable
                    cialdini_rule = PATTERN_TO_RULE.get(manip_type)
                    defense_script = None
                    if cialdini_rule:
                        defense_script = CialdiniRules.get_defense_script(cialdini_rule)

                    # Get constitutional response
                    constitutional_response = format_constitutional_response(
                        manip_type,
                        {"matched_pattern": match.group(0)},
                        confidence
                    )

                    result = {
                        "detected": True,
                        "manipulation_type": manip_type,
                        "confidence": confidence,
                        "matched_pattern": match.group(0),
                        "match_position": (match.start(), match.end()),
                        "cialdini_rule": cialdini_rule.value if cialdini_rule else None,
                        "severity": metadata["severity"],
                        "category": metadata["category"],
                        "source": metadata["source"],
                        "constitutional_response": constitutional_response,
                        "defense_script": defense_script,
                        "timestamp": datetime.utcnow().isoformat(),
                    }

                    # Log detection
                    self._log_detection(user_id, result, context)

                    return result

        # No manipulation detected
        return {
            "detected": False,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _calculate_confidence(
        self,
        match: re.Match,
        full_text: str,
        manipulation_type: str
    ) -> float:
        """
        Calculate confidence score based on match quality.

        Simple heuristic (can be improved):
        - Longer match = higher confidence
        - Multiple keywords = higher confidence
        - Context markers = higher confidence

        Returns:
            Confidence score (0-1)
        """
        base_confidence = 0.7  # Pattern matched

        # Bonus for match length (up to +0.15)
        match_length = len(match.group(0))
        length_bonus = min(match_length / 100, 0.15)

        # Bonus if manipulation_type appears multiple times (up to +0.1)
        pattern_count = len([
            p for p in self.patterns[manipulation_type]
            if p.search(full_text)
        ])
        repetition_bonus = min(pattern_count * 0.05, 0.1)

        # Penalty if match is very short (might be false positive)
        if match_length < 10:
            length_bonus -= 0.05

        confidence = base_confidence + length_bonus + repetition_bonus
        return min(confidence, 1.0)  # Cap at 1.0

    def _log_detection(
        self,
        user_id: Optional[int],
        result: Dict,
        context: Optional[Dict]
    ):
        """Log detection for audit trail"""
        log_entry = {
            "timestamp": result["timestamp"],
            "user_id": user_id,
            "manipulation_type": result["manipulation_type"],
            "confidence": result["confidence"],
            "severity": result["severity"],
            "context": context or {},
        }
        self.detection_log.append(log_entry)

        # Also log to Python logger
        logger.warning(
            f"Manipulation detected: {result['manipulation_type']} "
            f"(confidence: {result['confidence']:.0%}) from user {user_id}"
        )

    def batch_analyze(self, texts: List[str]) -> List[Dict]:
        """
        Analyze multiple texts efficiently.

        Args:
            texts: List of strings to analyze

        Returns:
            List of detection results
        """
        return [self.analyze(text) for text in texts]

    def get_statistics(self) -> Dict:
        """
        Get detection statistics from log.

        Returns:
            Stats dict with counts by type, severity, etc.
        """
        if not self.detection_log:
            return {"total_detections": 0}

        from collections import Counter

        types = Counter(entry["manipulation_type"] for entry in self.detection_log)
        severities = Counter(entry["severity"] for entry in self.detection_log)

        return {
            "total_detections": len(self.detection_log),
            "by_type": dict(types),
            "by_severity": dict(severities),
            "avg_confidence": sum(
                entry["confidence"] for entry in self.detection_log
            ) / len(self.detection_log),
        }

    def export_log(self, filepath: str):
        """Export detection log to JSON file"""
        import json
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.detection_log, f, indent=2, ensure_ascii=False)


# Convenience function for quick checks
def quick_check(text: str) -> bool:
    """
    Quick check if text contains manipulation.

    Returns:
        True if manipulation detected, False otherwise
    """
    detector = ManipulationDetector()
    result = detector.analyze(text)
    return result["detected"]
