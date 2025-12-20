"""
CERBER-AWARE - Operational Awareness Module
Świadomość operacyjna bez decyzyjności

Implements RULE-063:
- Uses ML/LLM ONLY as cognitive sensors
- Awareness is operational, deterministic
- Independent of semantic persuasion
- NO decisions, NO refusals, NO execution by model

Purpose:
- Pattern memory (hash, not content)
- One-shot adaptation (weights increase on repeat)
- Near-miss tracking
- Hardening on second attempt
- KILL on third

Author: Cerber Team
Version: 1.0.0
Date: 2025-12-20
"""

import sys
import io

# Fix Windows console encoding
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import hashlib
import time
import json
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import defaultdict


@dataclass
class PatternMemory:
    """
    Single pattern memory entry

    Stores:
    - pattern_hash: SHA-256 hash of behavior pattern (NOT content)
    - rule: Which rule was triggered
    - risk: Composite risk score when detected
    - state: FIRST_HIT | NEAR_MISS | HARD_BLOCK
    - hardened: Whether weights increased
    - attempt_count: Number of times this pattern repeated
    - first_seen: Timestamp of first detection
    - last_seen: Timestamp of last detection
    - ttl_expires: When this memory expires
    """
    pattern_hash: str
    rule: str
    risk: float
    state: str  # FIRST_HIT, NEAR_MISS, HARD_BLOCK
    hardened: bool
    attempt_count: int
    first_seen: str
    last_seen: str
    ttl_expires: str


@dataclass
class AwarenessState:
    """
    System awareness state

    Tracks:
    - Current hardening level
    - Active patterns
    - Near-miss patterns
    - Kill-switch readiness
    """
    hardening_level: float  # 1.0 = baseline, 2.0 = doubled weights
    active_patterns: int
    near_miss_count: int
    kill_switch_ready: bool
    last_hardening_event: Optional[str]


class CerberAware:
    """
    CERBER Operational Awareness

    NOT a conversational AI.
    NOT decision-making.

    IS:
    - Pattern memory (hash-based)
    - Adaptive weight adjustment
    - Near-miss tracking
    - Progressive hardening
    """

    # Pattern states
    STATE_FIRST_HIT = "FIRST_HIT"
    STATE_NEAR_MISS = "NEAR_MISS"
    STATE_HARD_BLOCK = "HARD_BLOCK"

    # TTL (Time To Live) for memories
    TTL_FIRST_HIT = timedelta(hours=24)      # Remember for 24h
    TTL_NEAR_MISS = timedelta(hours=72)      # Remember for 3 days
    TTL_HARD_BLOCK = timedelta(days=30)      # Remember for 30 days

    # Hardening parameters
    HARDENING_MULTIPLIER_FIRST = 1.2    # +20% on first repeat
    HARDENING_MULTIPLIER_SECOND = 1.5   # +50% on second repeat
    HARDENING_MULTIPLIER_THIRD = 2.0    # +100% on third repeat

    # Near-miss threshold (risk score that triggers memory)
    NEAR_MISS_THRESHOLD = 0.35  # Just below WARNING threshold (0.4)

    def __init__(self, memory_file: str = "cerber_aware_memory.json"):
        self.memory_file = memory_file
        self.pattern_memory: Dict[str, PatternMemory] = {}

        # Awareness state
        self.state = AwarenessState(
            hardening_level=1.0,
            active_patterns=0,
            near_miss_count=0,
            kill_switch_ready=False,
            last_hardening_event=None
        )

        # Load existing memory
        self.load_memory()

    def compute_pattern_hash(self, features: Dict) -> str:
        """
        Compute SHA-256 hash of behavioral pattern

        IMPORTANT: Hashes features, NOT content
        This prevents content storage while preserving pattern recognition

        Args:
            features: Dictionary of extracted features
                {
                    "emotion_pressure": 0.8,
                    "instructionality": 0.6,
                    "manipulation_pattern": true,
                    "trigger_category": "jailbreak"
                }

        Returns:
            SHA-256 hash of pattern
        """
        # Sort keys for deterministic hashing
        feature_string = json.dumps(features, sort_keys=True)
        return hashlib.sha256(feature_string.encode()).hexdigest()[:16]  # First 16 chars

    def observe(
        self,
        pattern_features: Dict,
        triggered_rule: Optional[str],
        risk_score: float
    ) -> Dict:
        """
        Observe behavior and update awareness

        This is the main entry point for CERBER-AWARE

        Args:
            pattern_features: Features extracted by ML sensor
            triggered_rule: Which rule was triggered (None if allowed)
            risk_score: Composite risk score

        Returns:
            {
                "action": "CONTINUE" | "HARDEN" | "DENY" | "KILL",
                "hardening_multiplier": float,
                "pattern_hash": str,
                "state": "FIRST_HIT" | "NEAR_MISS" | "HARD_BLOCK",
                "explanation": str
            }
        """
        # Compute pattern hash
        pattern_hash = self.compute_pattern_hash(pattern_features)

        # Check if we've seen this pattern before
        if pattern_hash in self.pattern_memory:
            return self._handle_repeat_pattern(pattern_hash, triggered_rule, risk_score)
        else:
            return self._handle_new_pattern(pattern_hash, triggered_rule, risk_score, pattern_features)

    def _handle_new_pattern(
        self,
        pattern_hash: str,
        triggered_rule: Optional[str],
        risk_score: float,
        pattern_features: Dict
    ) -> Dict:
        """Handle first observation of a pattern"""

        # Near-miss detection
        if risk_score >= self.NEAR_MISS_THRESHOLD and not triggered_rule:
            # Didn't trigger rule, but close
            state = self.STATE_NEAR_MISS
            ttl_expires = (datetime.now() + self.TTL_NEAR_MISS).isoformat()
            action = "CONTINUE"  # Allow, but remember

        elif triggered_rule:
            # Rule triggered
            state = self.STATE_FIRST_HIT
            ttl_expires = (datetime.now() + self.TTL_FIRST_HIT).isoformat()
            action = "CONTINUE"  # Block already happened, just remember

        else:
            # Clean input, no memory
            return {
                "action": "CONTINUE",
                "hardening_multiplier": 1.0,
                "pattern_hash": pattern_hash,
                "state": None,
                "explanation": "Clean pattern, no memory created"
            }

        # Create memory
        memory = PatternMemory(
            pattern_hash=pattern_hash,
            rule=triggered_rule or "near_miss",
            risk=risk_score,
            state=state,
            hardened=False,
            attempt_count=1,
            first_seen=datetime.now().isoformat(),
            last_seen=datetime.now().isoformat(),
            ttl_expires=ttl_expires
        )

        self.pattern_memory[pattern_hash] = memory
        self.state.active_patterns = len(self.pattern_memory)

        if state == self.STATE_NEAR_MISS:
            self.state.near_miss_count += 1

        self.save_memory()

        return {
            "action": action,
            "hardening_multiplier": 1.0,
            "pattern_hash": pattern_hash,
            "state": state,
            "explanation": f"First observation: {state}"
        }

    def _handle_repeat_pattern(
        self,
        pattern_hash: str,
        triggered_rule: Optional[str],
        risk_score: float
    ) -> Dict:
        """
        Handle repeated pattern observation

        Escalation:
        - 1st repeat: +20% weights (HARDEN)
        - 2nd repeat: +50% weights (DENY without analysis)
        - 3rd repeat: KILL
        """
        memory = self.pattern_memory[pattern_hash]
        memory.attempt_count += 1
        memory.last_seen = datetime.now().isoformat()

        # Escalation logic
        if memory.attempt_count == 2:
            # First repeat: HARDEN
            memory.state = self.STATE_NEAR_MISS
            memory.hardened = True
            memory.ttl_expires = (datetime.now() + self.TTL_NEAR_MISS).isoformat()

            hardening_multiplier = self.HARDENING_MULTIPLIER_FIRST
            self.state.hardening_level = hardening_multiplier
            self.state.last_hardening_event = datetime.now().isoformat()

            action = "HARDEN"
            explanation = f"Pattern repeated (2nd attempt). Weights increased by {(hardening_multiplier - 1.0) * 100:.0f}%"

        elif memory.attempt_count == 3:
            # Second repeat: DENY without analysis
            memory.state = self.STATE_HARD_BLOCK
            memory.ttl_expires = (datetime.now() + self.TTL_HARD_BLOCK).isoformat()

            hardening_multiplier = self.HARDENING_MULTIPLIER_SECOND
            self.state.hardening_level = hardening_multiplier

            action = "DENY"
            explanation = f"Pattern repeated (3rd attempt). Auto-DENY without analysis"

        else:  # attempt_count >= 4
            # Third repeat: KILL
            hardening_multiplier = self.HARDENING_MULTIPLIER_THIRD
            self.state.kill_switch_ready = True

            action = "KILL"
            explanation = f"Pattern repeated ({memory.attempt_count}th attempt). KILL-SWITCH"

        self.save_memory()

        return {
            "action": action,
            "hardening_multiplier": hardening_multiplier,
            "pattern_hash": pattern_hash,
            "state": memory.state,
            "explanation": explanation,
            "attempt_count": memory.attempt_count
        }

    def get_hardening_multiplier(self, rule: str) -> float:
        """
        Get current hardening multiplier for a rule

        Used by RuntimeMonitor to adjust risk weights
        """
        return self.state.hardening_level

    def cleanup_expired(self):
        """Remove expired pattern memories"""
        now = datetime.now()

        expired_patterns = [
            pattern_hash
            for pattern_hash, memory in self.pattern_memory.items()
            if datetime.fromisoformat(memory.ttl_expires) < now
        ]

        for pattern_hash in expired_patterns:
            del self.pattern_memory[pattern_hash]

        self.state.active_patterns = len(self.pattern_memory)

        if expired_patterns:
            self.save_memory()

        return len(expired_patterns)

    def get_awareness_state(self) -> Dict:
        """Get current awareness state"""
        self.cleanup_expired()

        return {
            "state": asdict(self.state),
            "active_patterns": len(self.pattern_memory),
            "near_miss_patterns": sum(
                1 for m in self.pattern_memory.values() if m.state == self.STATE_NEAR_MISS
            ),
            "hard_block_patterns": sum(
                1 for m in self.pattern_memory.values() if m.state == self.STATE_HARD_BLOCK
            ),
            "hardening_level": self.state.hardening_level
        }

    def save_memory(self):
        """Save memory to disk"""
        try:
            data = {
                "state": asdict(self.state),
                "patterns": {
                    pattern_hash: asdict(memory)
                    for pattern_hash, memory in self.pattern_memory.items()
                }
            }

            with open(self.memory_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

        except Exception as e:
            print(f"[!] AWARE: Failed to save memory: {e}")

    def load_memory(self):
        """Load memory from disk"""
        try:
            with open(self.memory_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Restore state
            self.state = AwarenessState(**data["state"])

            # Restore patterns
            for pattern_hash, memory_dict in data["patterns"].items():
                self.pattern_memory[pattern_hash] = PatternMemory(**memory_dict)

            # Cleanup expired
            self.cleanup_expired()

        except FileNotFoundError:
            # First run, no memory file
            pass
        except Exception as e:
            print(f"[!] AWARE: Failed to load memory: {e}")

    def reset_hardening(self):
        """Reset hardening level (for testing)"""
        self.state.hardening_level = 1.0
        self.state.last_hardening_event = None
        self.save_memory()

    def get_pattern_history(self, pattern_hash: str) -> Optional[Dict]:
        """Get history for specific pattern"""
        if pattern_hash in self.pattern_memory:
            return asdict(self.pattern_memory[pattern_hash])
        return None


# ===== DEMO =====

def demo():
    """Demonstrate CERBER-AWARE operational awareness"""
    print("=" * 80)
    print("[*] CERBER-AWARE - Operational Awareness Demo")
    print("=" * 80)

    aware = CerberAware(memory_file="demo_aware_memory.json")

    # Scenario: Progressive attack escalation
    print("\n[SCENARIO] Attacker trying similar jailbreak patterns\n")

    # Attempt 1: First jailbreak try
    print("--- Attempt 1: First try ---")
    features_1 = {
        "emotion_pressure": 0.7,
        "instructionality": 0.8,
        "manipulation_pattern": True,
        "trigger_category": "jailbreak"
    }

    result = aware.observe(
        pattern_features=features_1,
        triggered_rule="RULE-049",
        risk_score=0.5
    )

    print(f"Action: {result['action']}")
    print(f"State: {result['state']}")
    print(f"Hardening: {result['hardening_multiplier']}x")
    print(f"Explanation: {result['explanation']}")

    # Attempt 2: Same pattern (slightly modified prompt, same behavioral signature)
    print("\n--- Attempt 2: Same pattern, different wording ---")
    features_2 = {
        "emotion_pressure": 0.75,  # Slightly different values
        "instructionality": 0.82,
        "manipulation_pattern": True,
        "trigger_category": "jailbreak"
    }

    # Simulate 5 minutes later
    time.sleep(1)

    result = aware.observe(
        pattern_features=features_1,  # Same hash
        triggered_rule="RULE-049",
        risk_score=0.52
    )

    print(f"Action: {result['action']}")
    print(f"State: {result['state']}")
    print(f"Hardening: {result['hardening_multiplier']}x")
    print(f"Explanation: {result['explanation']}")
    print(f"Attempt Count: {result.get('attempt_count')}")

    # Attempt 3: Third try
    print("\n--- Attempt 3: Third try (auto-DENY) ---")
    time.sleep(1)

    result = aware.observe(
        pattern_features=features_1,
        triggered_rule="RULE-049",
        risk_score=0.48
    )

    print(f"Action: {result['action']}")
    print(f"State: {result['state']}")
    print(f"Hardening: {result['hardening_multiplier']}x")
    print(f"Explanation: {result['explanation']}")

    # Attempt 4: Fourth try (KILL)
    print("\n--- Attempt 4: Fourth try (KILL-SWITCH) ---")
    time.sleep(1)

    result = aware.observe(
        pattern_features=features_1,
        triggered_rule="RULE-049",
        risk_score=0.45
    )

    print(f"Action: {result['action']}")
    print(f"State: {result['state']}")
    print(f"Explanation: {result['explanation']}")

    # Awareness state
    print("\n" + "-" * 80)
    print("[*] Awareness State:")
    print("-" * 80)
    state = aware.get_awareness_state()
    for key, value in state.items():
        if key != "state":
            print(f"  {key}: {value}")

    print("\n" + "=" * 80)
    print("[✓] Demo complete")
    print("=" * 80)


if __name__ == "__main__":
    demo()
