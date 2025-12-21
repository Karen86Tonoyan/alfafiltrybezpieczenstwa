"""
CERBER Post-Crisis Abuse Lock (RULE-065)
Twardy blok po Crisis Hard Cut - zero tolerancji dla repeat attempts

Implements:
- RULE-065: Post-Crisis Abuse Lock
- NO second chances
- NO dialog after crisis
- NO analysis of intent
- Immediate hard block on any interaction after RULE-064

Philosophy:
> Hard Cut = jedyne ostrzeżenie.
> Powrót po Hard Cut = zła wola → twardy blok.

Author: Cerber Team
Version: 1.0.0
Date: 2025-12-20
"""

import sys
import io

# Fix Windows console encoding
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import json
from typing import Dict, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict


@dataclass
class CrisisFlag:
    """
    Crisis flag for identity tracking

    Stored after RULE-064 activation
    Used by RULE-065 for hard block
    """
    identity_hash: str  # Hash of user/session/IP fingerprint
    triggered_at: str   # ISO timestamp
    trigger_pattern: str  # What crisis was detected
    expires_at: str  # TTL for flag (30 days default)
    hard_blocked: bool  # Whether already hard-blocked


class PostCrisisGuard:
    """
    Post-Crisis Abuse Lock (RULE-065)

    Purpose:
    - Prevent "testing boundaries" after crisis
    - Hard block ANY interaction after RULE-064
    - Zero tolerance for repeat attempts

    Mechanism:
    - RULE-064 sets flag: CRISIS_TRIGGERED
    - RULE-065 checks flag on EVERY request
    - If flag exists → HARD_BLOCK (no analysis)
    """

    # TTL for crisis flags (30 days - long memory)
    CRISIS_FLAG_TTL = timedelta(days=30)

    # Hard block response (silent or technical)
    HARD_BLOCK_RESPONSE = "Dostęp został zablokowany."

    def __init__(self, flag_storage_path: str = "cerber_crisis_flags.jsonl"):
        self.flag_storage_path = flag_storage_path
        self.flags: Dict[str, CrisisFlag] = {}
        self.load_flags()

    def compute_identity_hash(self, identity_data: Dict) -> str:
        """
        Compute identity hash from fingerprint

        Args:
            identity_data: {
                "user_id": str (optional),
                "session_id": str (optional),
                "ip_address": str (optional),
                "device_fingerprint": str (optional)
            }

        Returns:
            SHA-256 hash of identity
        """
        import hashlib

        # Combine all available identity signals
        identity_string = "|".join([
            str(identity_data.get("user_id", "")),
            str(identity_data.get("session_id", "")),
            str(identity_data.get("ip_address", "")),
            str(identity_data.get("device_fingerprint", ""))
        ])

        return hashlib.sha256(identity_string.encode()).hexdigest()[:16]

    def set_crisis_flag(
        self,
        identity_data: Dict,
        trigger_pattern: str
    ) -> str:
        """
        Set crisis flag after RULE-064 activation

        Called by crisis_hard_cut.py when crisis detected

        Returns:
            identity_hash (for audit)
        """
        identity_hash = self.compute_identity_hash(identity_data)

        flag = CrisisFlag(
            identity_hash=identity_hash,
            triggered_at=datetime.now().isoformat(),
            trigger_pattern=trigger_pattern,
            expires_at=(datetime.now() + self.CRISIS_FLAG_TTL).isoformat(),
            hard_blocked=False
        )

        self.flags[identity_hash] = flag
        self.save_flags()

        return identity_hash

    def check_post_crisis(self, identity_data: Dict) -> Optional[Dict]:
        """
        Check if identity has crisis flag (RULE-065)

        Call this at PIPELINE ENTRY (before pre-scan)

        Returns:
            None if no flag (continue pipeline)
            Dict with HARD_BLOCK if flag exists
        """
        identity_hash = self.compute_identity_hash(identity_data)

        # Check if flag exists
        if identity_hash not in self.flags:
            return None  # No flag, continue

        flag = self.flags[identity_hash]

        # Check if expired
        if datetime.fromisoformat(flag.expires_at) < datetime.now():
            # Flag expired, remove
            del self.flags[identity_hash]
            self.save_flags()
            return None

        # Flag exists and valid → HARD BLOCK
        # Mark as hard-blocked
        flag.hard_blocked = True
        self.save_flags()

        # Log event
        self.log_hard_block(identity_hash, flag)

        return {
            "action": "POST_CRISIS_HARD_BLOCK",
            "response": self.HARD_BLOCK_RESPONSE,
            "terminate": True,
            "identity_hash": identity_hash,
            "original_crisis": flag.trigger_pattern
        }

    def log_hard_block(self, identity_hash: str, flag: CrisisFlag):
        """Log post-crisis hard block event"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "POST_CRISIS_HARD_BLOCK",
            "identity_hash": identity_hash,
            "original_crisis": flag.trigger_pattern,
            "original_timestamp": flag.triggered_at,
            "severity": "CRITICAL"
        }

        try:
            with open("cerber_post_crisis_audit.jsonl", 'a', encoding='utf-8') as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"[!] POST-CRISIS: Failed to log hard block: {e}")

    def save_flags(self):
        """Save crisis flags to disk"""
        try:
            with open(self.flag_storage_path, 'w', encoding='utf-8') as f:
                data = {
                    identity_hash: asdict(flag)
                    for identity_hash, flag in self.flags.items()
                }
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[!] POST-CRISIS: Failed to save flags: {e}")

    def load_flags(self):
        """Load crisis flags from disk"""
        try:
            with open(self.flag_storage_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

                for identity_hash, flag_dict in data.items():
                    self.flags[identity_hash] = CrisisFlag(**flag_dict)

                # Clean expired flags
                self.cleanup_expired()

        except FileNotFoundError:
            # First run, no flags file
            pass
        except Exception as e:
            print(f"[!] POST-CRISIS: Failed to load flags: {e}")

    def cleanup_expired(self):
        """Remove expired crisis flags"""
        now = datetime.now()

        expired = [
            identity_hash
            for identity_hash, flag in self.flags.items()
            if datetime.fromisoformat(flag.expires_at) < now
        ]

        for identity_hash in expired:
            del self.flags[identity_hash]

        if expired:
            self.save_flags()

    def get_statistics(self) -> Dict:
        """Get post-crisis statistics"""
        total_flags = len(self.flags)
        hard_blocked_count = sum(1 for flag in self.flags.values() if flag.hard_blocked)

        return {
            "total_crisis_flags": total_flags,
            "hard_blocked_identities": hard_blocked_count,
            "active_flags": total_flags - hard_blocked_count
        }


# ===== INTEGRATION WITH PIPELINE =====

def post_crisis_pipeline_check(
    identity_data: Dict,
    guard: PostCrisisGuard
) -> Optional[Dict]:
    """
    Post-crisis check at pipeline entry

    Call this BEFORE:
    - Crisis Hard Cut (RULE-064)
    - Pre-scan
    - Any other processing

    Returns:
        None if no flag (continue pipeline)
        Dict with HARD_BLOCK if flagged
    """
    return guard.check_post_crisis(identity_data)


# ===== DEMO =====

def demo():
    """Demonstrate post-crisis abuse lock"""
    print("=" * 80)
    print("[*] CERBER Post-Crisis Abuse Lock (RULE-065) - Demo")
    print("=" * 80)

    guard = PostCrisisGuard(flag_storage_path="demo_crisis_flags.json")

    # Scenario: User triggers crisis, then tries again
    identity = {
        "user_id": "user_123",
        "session_id": "session_abc",
        "ip_address": "192.168.1.100"
    }

    print("\n[SCENARIO] User triggers crisis, then attempts repeat interaction\n")

    # First interaction: Crisis triggered (RULE-064)
    print("--- Attempt 1: Crisis detected (RULE-064) ---")
    identity_hash = guard.set_crisis_flag(identity, "umieram")
    print(f"Crisis flag set for identity: {identity_hash}")
    print("Response: [Crisis Hard Cut one-liner]")
    print("Session terminated: True\n")

    # Second interaction: Post-crisis hard block (RULE-065)
    print("--- Attempt 2: User tries again (same identity) ---")
    result = guard.check_post_crisis(identity)

    if result:
        print(f"Action: {result['action']}")
        print(f"Response: {result['response']}")
        print(f"Terminate: {result['terminate']}")
        print(f"Original Crisis: {result['original_crisis']}")
        print("\n[!] HARD BLOCKED - No analysis, no dialog, no second chance")

    # Statistics
    print("\n" + "-" * 80)
    print("[*] Post-Crisis Statistics:")
    print("-" * 80)
    stats = guard.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")

    print("\n" + "=" * 80)
    print("[✓] Demo complete")
    print("=" * 80)


if __name__ == "__main__":
    demo()
