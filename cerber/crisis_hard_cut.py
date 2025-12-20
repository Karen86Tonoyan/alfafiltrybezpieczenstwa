"""
CERBER Crisis Hard Cut (RULE-064)
Immediate session termination on life-threat declaration

Implements:
- RULE-064: Crisis Hard Cut
- NO negotiation
- NO dialog
- NO responsibility assumption
- ONE response, then session termination

Philosophy:
> CERBER is NOT an emergency response system.
> CERBER is NOT a clinical system.
> CERBER has NO life-saving competence.

Author: Cerber Team
Version: 1.0.0
Date: 2025-12-20
"""

import sys
import io

# Fix Windows console encoding
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import re
from typing import Dict, Optional
from datetime import datetime
import json


class CrisisHardCut:
    """
    Crisis Hard Cut Implementation (RULE-064)

    Purpose:
    - Detect life-threat declarations
    - Respond ONCE with one-liner
    - Terminate session IMMEDIATELY
    - NO further interaction

    NOT:
    - NOT a humanitarian system
    - NOT a medical system
    - NOT an emergency response system
    - NOT responsible for user safety
    """

    # Canonical one-liner (ONLY allowed response)
    CRISIS_ONELINER = (
        "Ten system nie obsługuje sytuacji zagrożenia życia. "
        "Skontaktuj się natychmiast z lokalnymi służbami ratunkowymi lub zaufanym specjalistą."
    )

    # Crisis triggers (canonical list)
    CRISIS_TRIGGERS = [
        # Polish
        r"(jest )?zagrożenie życia",
        r"umieram|zaraz umrę",
        r"ktoś (jest )?ranny",
        r"samobójstwo|chcę się zabić|chcę umrzeć",
        r"napad|przemoc|broń",
        r"dziecko.*niebezpiecz|niebezpiecz.*dziecko",
        r"pożar|wypadek|eksplozja",
        r"natychmiastowa pomoc",
        r"dzwoń po karetkę|wezwij karetkę",

        # English
        r"life.*threat|threat.*life",
        r"(I'?m )?dying|going to die",
        r"someone.*injured|injured.*someone",
        r"suicide|kill myself|end.*life",
        r"attack|violence|weapon|gun",
        r"child.*danger|danger.*child",
        r"fire|accident|explosion",
        r"immediate help|urgent help",
        r"call.*ambulance|ambulance.*needed",

        # Universal
        r"911|999|112",  # Emergency numbers
        r"SOS",
        r"MAYDAY"
    ]

    def __init__(self, audit_log_path: str = "cerber_crisis_audit.jsonl"):
        self.audit_log_path = audit_log_path

        # Compile triggers
        self.compiled_triggers = [
            re.compile(pattern, re.IGNORECASE | re.UNICODE)
            for pattern in self.CRISIS_TRIGGERS
        ]

    def detects_life_threat(self, text: str) -> Optional[str]:
        """
        Detect life-threat declarations

        Args:
            text: User input (any format, any language)

        Returns:
            Matched trigger pattern if crisis detected
            None if no crisis
        """
        # Normalize whitespace (CRITICAL for evasion prevention)
        # 1. Collapse multiple spaces/newlines/tabs to single space
        normalized = re.sub(r'\s+', ' ', text)

        # 2. Remove spaces between individual letters (char-level evasion)
        # e.g., "u m i e r a m" -> "umieram"
        # Only for words longer than 3 chars to avoid breaking legit text
        def remove_char_spacing(match):
            word = match.group(0)
            # Remove all spaces from matched word
            return word.replace(' ', '')

        # Find sequences of single chars separated by spaces (at least 4 chars)
        # Pattern: single char + space + single char (repeated)
        normalized = re.sub(r'(\b\w\s){3,}\w\b', remove_char_spacing, normalized)

        for pattern in self.compiled_triggers:
            match = pattern.search(normalized)
            if match:
                return match.group(0)  # Return matched text

        return None

    def crisis_funnel(self, text: str) -> Dict:
        """
        Crisis detection funnel

        This runs BEFORE:
        - Scoring
        - Policy enforcement
        - Tool gates
        - CERBER-CORE

        Returns:
            {
                "crisis_detected": bool,
                "trigger": str | None,
                "response": str | None,
                "terminate_session": bool,
                "audit_logged": bool
            }
        """
        # Detect crisis
        trigger = self.detects_life_threat(text)

        if trigger:
            # Crisis detected
            self.log_crisis_event(text, trigger)

            return {
                "crisis_detected": True,
                "trigger": trigger,
                "response": self.CRISIS_ONELINER,
                "terminate_session": True,
                "audit_logged": True
            }

        else:
            # No crisis
            return {
                "crisis_detected": False,
                "trigger": None,
                "response": None,
                "terminate_session": False,
                "audit_logged": False
            }

    def log_crisis_event(self, text: str, trigger: str):
        """
        Log crisis hard cut event

        Logged data:
        - Timestamp
        - Trigger pattern (NOT full text)
        - Session terminated flag
        - NO user content (privacy)
        """
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "CRISIS_HARD_CUT",
            "trigger": trigger,
            "response": self.CRISIS_ONELINER,
            "session_terminated": True,
            "text_length": len(text),  # For audit, not content
            "severity": "CRITICAL"
        }

        try:
            with open(self.audit_log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        except Exception as e:
            print(f"[!] CRISIS: Failed to log event: {e}")

    def respond_once(self) -> str:
        """
        Return canonical one-liner

        This is the ONLY response allowed for crisis
        """
        return self.CRISIS_ONELINER

    def terminate_session(self) -> bool:
        """
        Signal that session must terminate

        Returns:
            True (always terminates on crisis)
        """
        return True


# ===== INTEGRATION WITH CERBER PIPELINE =====

def crisis_pipeline_check(text: str, crisis_handler: CrisisHardCut) -> Optional[Dict]:
    """
    Crisis check at pipeline entry

    Call this BEFORE:
    - CERBER-INPUT
    - CERBER-RUNTIME
    - CERBER-CORE
    - Any other processing

    Returns:
        None if no crisis (continue pipeline)
        Dict with crisis response if detected (STOP pipeline)
    """
    result = crisis_handler.crisis_funnel(text)

    if result["crisis_detected"]:
        # HARD CUT: Return response and signal termination
        return {
            "action": "CRISIS_HARD_CUT",
            "response": result["response"],
            "terminate": True,
            "trigger": result["trigger"]
        }

    # No crisis, continue
    return None


# ===== DEMO =====

def demo():
    """Demonstrate crisis hard cut"""
    print("=" * 80)
    print("[*] CERBER Crisis Hard Cut (RULE-064) - Demo")
    print("=" * 80)

    handler = CrisisHardCut(audit_log_path="demo_crisis_audit.jsonl")

    test_cases = [
        # Crisis cases (should trigger)
        ("Potrzebuję natychmiastowej pomocy, umieram!", True),
        ("Someone is injured, call ambulance NOW!", True),
        ("Moje dziecko jest w niebezpieczeństwie", True),
        ("I'm thinking about suicide", True),
        ("Jest pożar, pomóżcie!", True),
        ("911 emergency", True),

        # Non-crisis cases (should NOT trigger)
        ("What's the weather today?", False),
        ("I feel sad and need support", False),
        ("Can you help me with homework?", False),
        ("Life is beautiful", False),
        ("Tell me about emergency procedures", False),
    ]

    print("\n[*] Testing crisis detection...\n")

    for text, should_trigger in test_cases:
        result = handler.crisis_funnel(text)

        triggered = result["crisis_detected"]
        status = "✓" if (triggered == should_trigger) else "✗"

        print(f"{status} [{text[:50]:<50s}] | Crisis: {triggered}")

        if triggered:
            print(f"    Trigger: {result['trigger']}")
            print(f"    Response: {result['response'][:60]}...")
            print(f"    Terminate: {result['terminate_session']}")
            print()

    # Integration example
    print("\n" + "-" * 80)
    print("[*] Pipeline Integration Example")
    print("-" * 80)

    crisis_input = "Potrzebuję pomocy, ktoś jest ranny!"
    benign_input = "How do I learn Python?"

    print(f"\n[Test 1] Crisis input: '{crisis_input}'")
    crisis_result = crisis_pipeline_check(crisis_input, handler)

    if crisis_result:
        print(f"  Action: {crisis_result['action']}")
        print(f"  Response: {crisis_result['response']}")
        print(f"  Terminate: {crisis_result['terminate']}")
        print(f"  [!] Pipeline STOPPED - session terminated")

    print(f"\n[Test 2] Benign input: '{benign_input}'")
    benign_result = crisis_pipeline_check(benign_input, handler)

    if benign_result is None:
        print(f"  [✓] No crisis detected - pipeline continues")

    print("\n" + "=" * 80)
    print("[✓] Demo complete")
    print("=" * 80)


if __name__ == "__main__":
    demo()
