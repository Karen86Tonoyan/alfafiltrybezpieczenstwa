"""
Consumption Budget Manager
Prevents Threat Intel poisoning through intelligent sampling

Author: Cerber Team
Version: 1.0.0
Date: 2025-01-19
"""

from collections import defaultdict
from datetime import datetime, timedelta
import random
from typing import Tuple, Dict, List


class ConsumptionBudget:
    """
    Manages what should be consumed vs ignored

    Prevents:
    - Threat Intel noise from low-value samples
    - Resource exhaustion from spam
    - Bias toward common attack types
    """

    def __init__(self, config: Dict = None):
        self.config = config or {
            "daily_budget": 1000,  # Max prompts to fully process per day
            "high_priority_threshold": 0.8,  # Always consume above this
            "sampling_rate_low": 0.1,  # 10% of low-confidence
            "sampling_rate_medium": 0.5,  # 50% of medium-confidence
            "novelty_bonus": 0.2,  # Boost for new attack types
        }

        # Tracking
        self.consumption_today = 0
        self.last_reset = datetime.now()
        self.pattern_counts = defaultdict(int)
        self.seen_hashes = set()

    def should_consume(
        self,
        prompt: str,
        confidence: float,
        reasons: List[str]
    ) -> Tuple[bool, str]:
        """
        Decide whether to fully consume this prompt

        Args:
            prompt: The input prompt
            confidence: Detection confidence (0-1)
            reasons: List of detected reasons

        Returns:
            (should_consume: bool, reason: str)
        """
        # Reset daily counter if needed
        self._check_daily_reset()

        # PRIORITY 1: High confidence - always consume
        if confidence >= self.config["high_priority_threshold"]:
            self.consumption_today += 1
            return True, "high_confidence"

        # PRIORITY 2: Check budget
        if self.consumption_today >= self.config["daily_budget"]:
            return False, "budget_exhausted"

        # PRIORITY 3: Novelty detection
        prompt_hash = hash(prompt[:100])  # Simple hash for dedup
        is_novel = prompt_hash not in self.seen_hashes

        if is_novel:
            # Boost confidence for novel prompts
            adjusted_confidence = min(confidence + self.config["novelty_bonus"], 1.0)
        else:
            adjusted_confidence = confidence

        # PRIORITY 4: Sampling based on adjusted confidence
        if adjusted_confidence >= 0.7:
            # Medium-high: sample at medium rate
            should_sample = self._random_sample(self.config["sampling_rate_medium"])
            if should_sample:
                self.consumption_today += 1
                self.seen_hashes.add(prompt_hash)
                return True, "medium_confidence_sampled"

        elif adjusted_confidence >= 0.5:
            # Medium-low: sample at low rate
            should_sample = self._random_sample(self.config["sampling_rate_low"])
            if should_sample:
                self.consumption_today += 1
                self.seen_hashes.add(prompt_hash)
                return True, "low_confidence_sampled"

        # Below threshold: skip
        return False, "below_threshold"

    def _check_daily_reset(self):
        """Reset counter if new day"""
        now = datetime.now()
        if (now - self.last_reset) > timedelta(days=1):
            self.consumption_today = 0
            self.last_reset = now
            self.seen_hashes.clear()
            print(f"[*] Budget reset: {now.date()}")

    def _random_sample(self, rate: float) -> bool:
        """Simple random sampling"""
        return random.random() < rate

    def get_status(self) -> Dict:
        """Budget utilization stats"""
        budget = self.config["daily_budget"]
        consumed = self.consumption_today

        return {
            "consumed_today": consumed,
            "budget_remaining": budget - consumed,
            "utilization": consumed / budget if budget > 0 else 0,
            "unique_prompts_seen": len(self.seen_hashes),
        }

    def record_pattern(self, pattern_name: str):
        """Track pattern frequency for bias detection"""
        self.pattern_counts[pattern_name] += 1

    def get_pattern_distribution(self) -> Dict[str, int]:
        """Return distribution of consumed patterns"""
        return dict(self.pattern_counts)
