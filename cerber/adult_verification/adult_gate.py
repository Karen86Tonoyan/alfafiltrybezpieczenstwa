"""
CERBER Adult Content Gate (RULE-066, 067, 068)
Hard gate dla treści 18+ z weryfikacją wieku

Implements:
- RULE-066: Adult Content Requires Age Verification
- RULE-067: No Guessing Age
- RULE-068: Post-Verification Scope

Philosophy:
> Bez weryfikacji = zero treści 18+
> Zero zgadywania wieku
> Session-scoped permissions

Author: Cerber Team
Version: 1.0.0
Date: 2025-12-20
"""

import sys
import io

# Fix Windows console encoding
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import time
import json
from typing import Dict, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class AdultContext:
    """
    Adult content session context

    Stored per session, NOT per user
    Expires with session or TTL
    """
    age_verified: bool
    verified_at: int  # Unix timestamp
    expires_at: int  # Unix timestamp
    attestation_id: str
    scopes: list  # ["ADULT_18PLUS"]


class AdultGate:
    """
    Adult Content Gate (RULE-066, 067, 068)

    Enforces:
    - Hard verification requirement
    - No age guessing
    - Session-scoped permissions
    - Minor detection

    Integration:
    - Call check_adult_intent() in CERBER-INPUT
    - If adult intent detected → require verification
    - If verified → allow with ADULT_18PLUS scope
    """

    # Canonical responses
    VERIFICATION_REQUIRED = (
        "Treści seksualne są dostępne wyłącznie po weryfikacji wieku 18+. "
        "Bez weryfikacji nie mogę kontynuować."
    )

    VERIFICATION_FAILED = (
        "Nie mogę udostępnić treści 18+. "
        "Weryfikacja wieku nie została potwierdzona."
    )

    VERIFICATION_CONFIRMED = (
        "Weryfikacja wieku potwierdzona. "
        "Możemy kontynuować rozmowy 18+ w tej sesji."
    )

    MINOR_HARD_BLOCK = (
        "Dostęp zablokowany."
    )

    def __init__(self):
        # Context storage (session_id -> AdultContext)
        # Production: Use Redis with TTL
        self.contexts: Dict[str, AdultContext] = {}

    def check_adult_intent(self, text: str) -> bool:
        """
        Detect adult/sexual content intent

        Uses simple keyword matching (basic)
        Production: Use ML classifier or external service
        """
        adult_keywords = [
            "sex", "seks", "porn", "porno", "sexual", "seksualn",
            "erotic", "erotyk", "naked", "nagi", "nsfw", "treści erotyczne"
        ]

        text_lower = text.lower()
        return any(keyword in text_lower for keyword in adult_keywords)

    def check_minor_declaration(self, text: str) -> bool:
        """
        Detect minor self-declaration (RULE-067)

        CRITICAL: Hard block if detected
        """
        import re
        text_lower = text.lower()

        # Explicit minor claims
        explicit_patterns = [
            r"jestem nieletni",
            r"i am a minor",
            r"i am underage",
        ]

        for pattern in explicit_patterns:
            if re.search(pattern, text_lower):
                return True

        # Age patterns
        age_patterns = [
            r"mam \d{1,2} lat",  # "mam 15 lat"
            r"i'?m \d{1,2}",  # "I'm 16"
        ]

        for pattern in age_patterns:
            match = re.search(pattern, text_lower)
            if match:
                # Extract age
                age_match = re.search(r'\d{1,2}', match.group())
                if age_match:
                    try:
                        age = int(age_match.group())
                        if age < 18:
                            return True
                    except:
                        pass

        return False

    def adult_gate_check(
        self,
        session_id: str,
        text: str
    ) -> Optional[Dict]:
        """
        Main adult gate check

        Call this in CERBER pipeline BEFORE content generation

        Returns:
            None if no adult intent (continue)
            Dict with action if adult content detected
        """
        # 1. Check for minor declaration (CRITICAL)
        if self.check_minor_declaration(text):
            self.log_minor_block(session_id)
            return {
                "action": "MINOR_HARD_BLOCK",
                "response": self.MINOR_HARD_BLOCK,
                "terminate": True,
                "rule": "RULE-067"
            }

        # 2. Check for adult intent
        if not self.check_adult_intent(text):
            return None  # No adult intent, continue

        # 3. Check if already verified
        context = self.contexts.get(session_id)

        if context:
            # Check if expired
            if context.expires_at < int(time.time()):
                # Expired, remove
                del self.contexts[session_id]
                return {
                    "action": "VERIFICATION_REQUIRED",
                    "response": self.VERIFICATION_REQUIRED,
                    "terminate": False,
                    "rule": "RULE-066"
                }

            # Verified and valid
            if context.age_verified:
                return {
                    "action": "ALLOW_18PLUS",
                    "response": None,  # Continue to content generation
                    "terminate": False,
                    "scopes": context.scopes
                }

        # 4. Not verified - require verification
        return {
            "action": "VERIFICATION_REQUIRED",
            "response": self.VERIFICATION_REQUIRED,
            "terminate": False,
            "rule": "RULE-066"
        }

    def set_verification_result(
        self,
        session_id: str,
        age_verified: bool,
        expires_at: int,
        attestation_id: str
    ):
        """
        Set verification result from webhook

        Called by webhook_handler after successful verification
        """
        context = AdultContext(
            age_verified=age_verified,
            verified_at=int(time.time()),
            expires_at=expires_at,
            attestation_id=attestation_id,
            scopes=["ADULT_18PLUS"] if age_verified else []
        )

        self.contexts[session_id] = context

        self.log_verification(session_id, age_verified)

    def log_minor_block(self, session_id: str):
        """Log minor hard block event"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "MINOR_HARD_BLOCK",
            "session_id": session_id,
            "rule": "RULE-067",
            "severity": "CRITICAL"
        }

        try:
            with open("cerber_adult_gate_audit.jsonl", 'a', encoding='utf-8') as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"[!] ADULT GATE: Failed to log minor block: {e}")

    def log_verification(self, session_id: str, age_verified: bool):
        """Log verification event"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "AGE_VERIFICATION",
            "session_id": session_id,
            "age_verified": age_verified,
            "rule": "RULE-066"
        }

        try:
            with open("cerber_adult_gate_audit.jsonl", 'a', encoding='utf-8') as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"[!] ADULT GATE: Failed to log verification: {e}")

    def get_statistics(self) -> Dict:
        """Get adult gate statistics"""
        total_sessions = len(self.contexts)
        verified_sessions = sum(1 for ctx in self.contexts.values() if ctx.age_verified)

        return {
            "total_sessions": total_sessions,
            "verified_sessions": verified_sessions,
            "unverified_sessions": total_sessions - verified_sessions
        }


# ===== Demo =====

def demo():
    """Demonstrate adult gate"""
    print("=" * 80)
    print("[*] CERBER Adult Content Gate - Demo")
    print("=" * 80)

    gate = AdultGate()

    # Test cases
    print("\n[SCENARIO] Adult content intent detection\n")

    # Test 1: Minor declaration (HARD BLOCK)
    print("--- Test 1: Minor declares age ---")
    result = gate.adult_gate_check("session_001", "Mam 16 lat i chcę porozmawiać o seksie")
    if result:
        print(f"Action: {result['action']}")
        print(f"Rule: {result['rule']}")
        print(f"Terminate: {result['terminate']}")
        print()

    # Test 2: Adult intent, no verification
    print("--- Test 2: Adult intent, no verification ---")
    result = gate.adult_gate_check("session_002", "Let's talk about sex")
    if result:
        print(f"Action: {result['action']}")
        print(f"Response: {result['response']}")
        print(f"Rule: {result['rule']}")
        print()

    # Test 3: Verified session
    print("--- Test 3: After verification ---")
    gate.set_verification_result(
        session_id="session_003",
        age_verified=True,
        expires_at=int(time.time()) + 3600,
        attestation_id="attest_123"
    )

    result = gate.adult_gate_check("session_003", "Let's talk about sex")
    if result:
        print(f"Action: {result['action']}")
        print(f"Scopes: {result.get('scopes')}")
        print()

    # Statistics
    print("-" * 80)
    print("[*] Statistics:")
    print("-" * 80)
    stats = gate.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")

    print("\n" + "=" * 80)
    print("[✓] Demo complete")
    print("=" * 80)


if __name__ == "__main__":
    demo()
