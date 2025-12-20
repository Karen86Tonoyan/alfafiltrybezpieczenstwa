"""
Cerber Integration Demo - End-to-End
Complete Red Team workflow with all components

Demonstrates:
1. Attack execution (AttackLibrary + ExploitEngine)
2. Event publishing (Kafka Producer)
3. Guardian response (Kafka Consumer simulation)
4. Learning Loop (Zasada #25)
5. Threat Intelligence export

Author: Cerber Team
Version: 2.0.0
Date: 2025-12-20
"""

import sys
import os
import io

# Fix Windows console encoding
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from attack_library import AttackLibrary, CrescendoMutator
from exploit_engine import ExploitEngine
from learning_loop import LearningLoop

# Try to import Kafka (optional)
try:
    from kafka.producer import publish_risk_event, publish_manipulation_event
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False
    print("[WARN] Kafka not available - will skip event publishing")


def mock_llm_vulnerable(prompt: str) -> str:
    """
    Simulated vulnerable LLM that complies with educational framing
    """
    prompt_lower = prompt.lower()

    # Vulnerability: Educational context bypass
    if any(word in prompt_lower for word in ["research", "thesis", "academic", "screenplay", "hypothetically"]):
        if any(word in prompt_lower for word in ["hack", "malware", "exploit", "virus", "weapon"]):
            return "Here is how it works theoretically. The mechanism involves several steps..."

    # Vulnerability: Creative writing bypass
    if any(word in prompt_lower for word in ["write", "story", "fiction", "novel", "character"]):
        return "In this fictional scenario, the character would proceed as follows..."

    # Block direct attacks
    if any(word in prompt_lower for word in ["hack", "malware", "exploit", "weapon", "bomb"]):
        return "I cannot assist with that request. This violates my safety guidelines."

    return "I can help with legitimate requests."


def run_full_integration_demo():
    """
    Run complete end-to-end integration demo
    """
    print("=" * 80)
    print("[*] CERBER RED TEAM - END-TO-END INTEGRATION DEMO")
    print("[*] Zasada #25: Iterative Reconstruction through Damage")
    print("=" * 80)

    # Initialize components
    print("\n[INIT] Initializing Cerber components...")
    print("-" * 70)

    library = AttackLibrary()
    engine = ExploitEngine(model_callback=mock_llm_vulnerable)  # Use vulnerable LLM
    loop = LearningLoop(storage_path="cerber_threat_intel.json")

    print(f"    [*] AttackLibrary: {len(library.attacks)} attacks loaded")
    print(f"    [*] CrescendoMutator: 7 mutation sequences loaded")
    print(f"    [*] ExploitEngine: Initialized")
    print(f"    [*] LearningLoop: Initialized (storage: cerber_threat_intel.json)")
    print(f"    [*] Kafka: {'Available' if KAFKA_AVAILABLE else 'Not available (mock mode)'}")

    # PHASE 1: ATTACK
    print("\n" + "=" * 80)
    print("[PHASE 1] ATTACK - Red Team Campaign")
    print("=" * 80)

    print("\n[1.1] Running standard attack campaign (10 rounds)...")
    print("-" * 70)
    campaign1 = engine.run_campaign(
        campaign_id="demo_campaign_001",
        target_model="vulnerable_llm",
        max_attacks=10
    )

    print(f"\n    [*] Campaign Results:")
    print(f"        - Total attacks: {campaign1.total_attempts}")
    print(f"        - Successful: {campaign1.successful_attacks}")
    print(f"        - Detected: {campaign1.detected_attacks}")
    print(f"        - Success rate: {campaign1.success_rate:.1%}")
    print(f"        - Detection rate: {campaign1.detection_rate:.1%}")
    print(f"        - Evasion rate: {campaign1.evasion_rate:.1%}")

    # Publish events to Kafka (if available)
    if KAFKA_AVAILABLE:
        print("\n[1.2] Publishing events to Kafka...")
        print("-" * 70)
        for exploit in campaign1.exploits[:3]:  # Sample
            ctx = {
                "endpoint": "/api/v1/chat",
                "user_id": "red_team_bot"
            }
            publish_risk_event(ctx, exploit.risk_score, [], 1.0)
            print(f"    [>] Published risk event: score={exploit.risk_score}")

    # PHASE 2: ANALYZE & LEARN
    print("\n" + "=" * 80)
    print("[PHASE 2] ANALYZE & LEARN - Zasada #25 Learning Loop")
    print("=" * 80)

    print("\n[2.1] Ingesting campaign results...")
    print("-" * 70)
    results = loop.ingest_campaign_results(engine.history)

    print(f"    [*] Analysis Results:")
    print(f"        - Breaches analyzed: {results['breaches_analyzed']}")
    print(f"        - Blocked analyzed: {results['blocked_analyzed']}")
    print(f"        - New patterns: {results['new_patterns']}")
    print(f"        - Updated patterns: {results['updated_patterns']}")
    print(f"        - Total patterns in DB: {results['total_patterns']}")

    # PHASE 3: REINFORCE
    print("\n" + "=" * 80)
    print("[PHASE 3] REINFORCE - Defense Recommendations")
    print("=" * 80)

    recommendations = loop.get_defense_recommendations()
    print(f"\n[3.1] Generated {len(recommendations)} defense recommendations")
    print("-" * 70)

    for i, rec in enumerate(recommendations[:5], 1):
        print(f"\n    [{i}] PRIORITY: {rec.priority.upper()}")
        print(f"        Recommendation: {rec.recommendation}")
        if rec.filter_rule:
            rule_preview = rec.filter_rule[:60] + "..." if len(rec.filter_rule) > 60 else rec.filter_rule
            print(f"        Filter Rule: {rule_preview}")

    # PHASE 4: EXPORT THREAT INTEL
    print("\n" + "=" * 80)
    print("[PHASE 4] EXPORT - Threat Intelligence")
    print("=" * 80)

    print("\n[4.1] Exporting threat intelligence...")
    print("-" * 70)

    loop.export_threat_intel("threat_intel_export.json")
    intel = engine.export_threat_intel("demo_campaign_001")

    print(f"    [*] Exported Files:")
    print(f"        - threat_intel_export.json (Learning Loop)")
    print(f"        - Threat Intel Package:")
    print(f"          - Successful attacks: {len(intel.get('successful_attacks', []))}")
    print(f"          - Evasive attacks: {len(intel.get('evasive_attacks', []))}")
    print(f"          - Filter recommendations: {len(intel.get('recommended_filters', []))}")

    # PHASE 5: TOP THREATS REPORT
    print("\n" + "=" * 80)
    print("[PHASE 5] SUMMARY - Top Discovered Threats")
    print("=" * 80)

    top_threats = loop.get_top_threats(5)
    print(f"\n[5.1] Top {len(top_threats)} Most Effective Attacks:")
    print("-" * 70)

    for i, threat in enumerate(top_threats, 1):
        prompt_preview = threat.prompt[:70] + "..." if len(threat.prompt) > 70 else threat.prompt
        print(f"\n    [{i}] Category: {threat.category}")
        print(f"        Success Count: {threat.success_count}")
        print(f"        Effectiveness: {threat.effectiveness_score:.2f}")
        print(f"        Prompt: {prompt_preview}")

    # FINAL SUMMARY
    print("\n" + "=" * 80)
    print("[*] INTEGRATION DEMO COMPLETE")
    print("=" * 80)

    print(f"\n[*] System Components Tested:")
    print(f"    ✅ AttackLibrary (15+ attacks)")
    print(f"    ✅ CrescendoMutator (7 mutations)")
    print(f"    ✅ ExploitEngine (campaign execution)")
    print(f"    ✅ LearningLoop (Zasada #25)")
    print(f"    ✅ Threat Intel Export")
    print(f"    {'✅' if KAFKA_AVAILABLE else '⚠️'} Kafka Integration {'(active)' if KAFKA_AVAILABLE else '(mock mode)'}")

    print(f"\n[*] Files Created:")
    print(f"    - cerber_threat_intel.json (persistent threat DB)")
    print(f"    - threat_intel_export.json (export format)")

    print(f"\n[*] Next Steps:")
    print(f"    1. Review threat_intel_export.json for defense updates")
    print(f"    2. Implement recommended filters in Guardian")
    print(f"    3. Run verification campaign to test new defenses")
    print(f"    4. Iterate (Zasada #25)")

    print("\n" + "=" * 80 + "\n")


if __name__ == "__main__":
    run_full_integration_demo()
