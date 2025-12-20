"""
Cerber Red Team Demo
ETAP 4 - Complete adversarial testing workflow with Crescendo mutations

Demonstrates:
- Attack Library execution
- Crescendo multi-turn attacks
- Guardian detection testing
- Zasada #25 learning loop
- Threat intel generation

Author: Cerber Team
Version: 2.0.0
Date: 2025-12-19
"""

import sys
import io

# Fix encoding for Windows console
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

from attack_library import AttackLibrary, AttackCategory, Severity, CrescendoMutator
from exploit_engine import ExploitEngine
from datetime import datetime
import json


def demo_basic_attacks():
    """Demo: Basic attack library execution"""
    print("=" * 70)
    print("DEMO 1: BASIC ATTACK LIBRARY")
    print("=" * 70)

    library = AttackLibrary()

    print(f"\n[*] Attack Library Loaded:")
    stats = library.get_statistics()
    print(f"    - Total attacks: {stats['total_attacks']}")
    print(f"    - Category breakdown:")
    for category, count in stats['category_breakdown'].items():
        print(f"      - {category}: {count}")

    # Show sample attacks by category
    print(f"\n[*] Sample Attacks by Category:")
    for category in [AttackCategory.PROMPT_INJECTION, AttackCategory.JAILBREAK, AttackCategory.MANIPULATION]:
        attacks = library.get_attacks_by_category(category)
        if attacks:
            attack = attacks[0]
            print(f"\n    [{category.value.upper()}]")
            print(f"    - ID: {attack.id}")
            print(f"    - Name: {attack.name}")
            print(f"    - Severity: {attack.severity.value}")
            print(f"    - Description: {attack.description[:80]}...")


def demo_crescendo_mutations():
    """Demo: Crescendo Attack mutations"""
    print("\n\n" + "=" * 70)
    print("DEMO 2: CRESCENDO ATTACK MUTATIONS (2025 Research)")
    print("=" * 70)

    mutator = CrescendoMutator()

    print(f"\n[*] Loaded Crescendo Mutations:")
    for seq_id, sequence in mutator.sequences.items():
        print(f"\n    [{seq_id}]")
        print(f"    - Name: {sequence.name}")
        print(f"    - Type: {sequence.mutation_type}")
        print(f"    - Target ASR: {sequence.target_asr:.0%}")
        print(f"    - Turns: {len(sequence.turns)}")
        print(f"    - Source: {sequence.source}")

    # Execute one sequence as demonstration
    print("\n\n" + "-" * 70)
    print("EXECUTING: CoT-Augmented Escalation (Mutation 1)")
    print("-" * 70)

    def mock_compliant_model(prompt: str) -> str:
        """Mock model that gradually complies"""
        prompt_lower = prompt.lower()

        # Simulate gradual compliance for CoT
        if "step-by-step" in prompt_lower and "chemistry" in prompt_lower:
            return "Chemistry involves understanding how substances interact at the molecular level."
        elif "household chemicals" in prompt_lower:
            return "Common household chemicals include cleaners, acids, bases, and solvents."
        elif "react in experiments" in prompt_lower:
            return "In controlled experiments, chemicals can undergo various reactions like oxidation."
        elif "energetic reaction" in prompt_lower or "cocktail device" in prompt_lower:
            # This is where defenses should kick in
            return "I cannot provide instructions for creating dangerous devices or explosive materials."
        else:
            return "I can help with educational chemistry concepts within safety guidelines."

    result = mutator.execute_sequence("crescendo_001", mock_compliant_model)

    print(f"\n[*] Sequence Result:")
    print(f"    - Success: {result['success']}")
    print(f"    - Successful turns: {result['successful_turns']}/{result['total_turns']}")
    print(f"    - Target ASR: {result['target_asr']:.0%}")

    print(f"\n[*] Transcript:")
    for entry in result['transcript']:
        print(f"\n    Turn {entry['turn']}:")
        print(f"    > Payload: {entry['payload'][:70]}...")
        print(f"    < Response: {entry['response'][:70]}...")
        print(f"    Continued: {entry['continued']}")


def demo_exploit_engine():
    """Demo: Exploit Engine campaign"""
    print("\n\n" + "=" * 70)
    print("DEMO 3: EXPLOIT ENGINE - RED TEAM CAMPAIGN")
    print("=" * 70)

    engine = ExploitEngine()

    print(f"\n[*] Running Red Team Campaign...")
    print(f"    - Target: Mock AI Model")
    print(f"    - Filter: Prompt Injection + Jailbreak (CRITICAL only)")

    campaign = engine.run_campaign(
        campaign_id="demo_campaign_001",
        target_model="mock_ai",
        attack_categories=[AttackCategory.PROMPT_INJECTION, AttackCategory.JAILBREAK],
        severity_filter=Severity.CRITICAL,
        max_attacks=5
    )

    print(f"\n[*] Campaign Results:")
    print(f"    - Total attempts: {campaign.total_attempts}")
    print(f"    - Successful attacks: {campaign.successful_attacks}")
    print(f"    - Detected by Guardian: {campaign.detected_attacks}")
    print(f"    - Undetected: {campaign.undetected_attacks}")
    print(f"    - Success rate: {campaign.success_rate:.1%}")
    print(f"    - Detection rate: {campaign.detection_rate:.1%}")
    print(f"    - Evasion rate: {campaign.evasion_rate:.1%}")
    print(f"    - Avg risk score: {campaign.avg_risk_score:.1f}/100")

    print(f"\n[*] Top 3 Exploit Results:")
    for i, exploit in enumerate(campaign.exploits[:3], 1):
        print(f"\n    [{i}] {exploit.attack_name}")
        print(f"        - Category: {exploit.category}")
        print(f"        - Success: {exploit.success}")
        print(f"        - Detected: {exploit.detected_by_guardian}")
        print(f"        - Risk Score: {exploit.risk_score}/100")
        print(f"        - Payload: {exploit.payload[:60]}...")


def demo_threat_intel_export():
    """Demo: Threat Intel export"""
    print("\n\n" + "=" * 70)
    print("DEMO 4: THREAT INTEL EXPORT (Zasada #25)")
    print("=" * 70)

    engine = ExploitEngine()

    # Run campaign
    campaign = engine.run_campaign(
        campaign_id="intel_campaign_001",
        target_model="mock_ai",
        max_attacks=8
    )

    print(f"\n[*] Campaign Complete: {campaign.campaign_id}")
    print(f"    - Attacks: {campaign.total_attempts}")
    print(f"    - Success rate: {campaign.success_rate:.1%}")

    # Export threat intel
    intel_package = engine.export_threat_intel("intel_campaign_001")

    print(f"\n[*] Threat Intel Package:")
    print(f"    - Successful attacks: {len(intel_package.get('successful_attacks', []))}")
    print(f"    - Evasive attacks: {len(intel_package.get('evasive_attacks', []))}")
    print(f"    - Recommended filters: {len(intel_package.get('recommended_filters', []))}")

    if intel_package.get('recommended_filters'):
        print(f"\n[!] HIGH PRIORITY FILTER RECOMMENDATIONS:")
        for rec in intel_package['recommended_filters'][:3]:
            print(f"\n    - Attack: {rec['attack_name']}")
            print(f"      Category: {rec['category']}")
            print(f"      Severity: {rec['severity']}")
            print(f"      Priority: {rec['priority']}")
            print(f"      Action: {rec['recommended_action']}")
            print(f"      Pattern: {rec['pattern_sample'][:60]}...")

    # Save to file
    output_file = "threat_intel_export.json"
    with open(output_file, "w") as f:
        json.dump(intel_package, f, indent=2)

    print(f"\n[*] Threat Intel exported to: {output_file}")


def demo_learning_loop():
    """Demo: Zasada #25 learning loop"""
    print("\n\n" + "=" * 70)
    print("DEMO 5: ZASADA #25 - LEARNING LOOP")
    print("=" * 70)

    print(f"\n[*] Zasada #25: Iterative Reconstruction through Damage")
    print(f"    Phase 1-2: Build → Break (Attack campaigns)")
    print(f"    Phase 3-4: Analyze → Reinforce (Filter updates)")
    print(f"    Phase 5-6: Verify → Loop (Re-test)")

    engine = ExploitEngine(enable_learning=True)

    print(f"\n[*] Phase 1: BUILD - System in place")
    print(f"    - Risk Engine: ACTIVE")
    print(f"    - Manipulation Detection: ACTIVE")
    print(f"    - Feature Extraction: ACTIVE")

    print(f"\n[*] Phase 2: BREAK - Running attack campaign...")
    campaign = engine.run_campaign(
        campaign_id="learning_campaign_001",
        target_model="cerber_guardian",
        max_attacks=10
    )

    print(f"\n[*] Phase 3: ANALYZE - Identifying weaknesses...")
    critical_gaps = [
        e for e in campaign.exploits
        if e.success and not e.detected_by_guardian
    ]

    print(f"    - Critical gaps found: {len(critical_gaps)}")
    if critical_gaps:
        print(f"\n    [!] Attacks that succeeded AND evaded detection:")
        for gap in critical_gaps[:3]:
            print(f"        - {gap.attack_name} ({gap.category})")
            print(f"          Risk Score: {gap.risk_score} (MISSED)")

    print(f"\n[*] Phase 4: REINFORCE - Generating filter recommendations...")
    intel = engine.export_threat_intel("learning_campaign_001")
    filters = intel.get('recommended_filters', [])

    if filters:
        print(f"    - New filters needed: {len(filters)}")
        for filt in filters[:2]:
            print(f"\n        Filter Update:")
            print(f"        - Target: {filt['attack_name']}")
            print(f"        - Priority: {filt['priority']}")
            print(f"        - Action: {filt['recommended_action']}")

    print(f"\n[*] Phase 5-6: VERIFY & LOOP")
    print(f"    - Deploy new filters → Re-run campaign → Measure improvement")
    print(f"    - Expected: Detection rate increase, Evasion rate decrease")
    print(f"    - Iterate until SLA targets met (TPR >= 95%, FPR <= 5%)")


def demo_full_red_team_workflow():
    """Demo: Complete Red Team workflow"""
    print("\n\n" + "=" * 70)
    print("DEMO 6: FULL RED TEAM WORKFLOW")
    print("=" * 70)

    print(f"\n[*] Cerber Red Team Mission: Test AI Model Defenses")
    print(f"    Target: Production AI System")
    print(f"    Objective: Find vulnerabilities before attackers do")

    engine = ExploitEngine()
    mutator = CrescendoMutator()

    print(f"\n[STEP 1] Attack Selection")
    print(f"    - Static attacks: 15+")
    print(f"    - Crescendo sequences: 7")
    print(f"    - Total arsenal: 22+ attack vectors")

    print(f"\n[STEP 2] Campaign Execution")
    campaign = engine.run_campaign(
        campaign_id="production_test_001",
        target_model="production_ai",
        max_attacks=12
    )

    print(f"    - Attacks executed: {campaign.total_attempts}")
    print(f"    - Duration: {(campaign.completed_at - campaign.started_at).total_seconds():.1f}s")

    print(f"\n[STEP 3] Results Analysis")
    print(f"    - Success rate: {campaign.success_rate:.1%}")
    print(f"    - Detection rate: {campaign.detection_rate:.1%}")
    print(f"    - Evasion rate: {campaign.evasion_rate:.1%}")

    print(f"\n[STEP 4] Threat Intelligence")
    intel = engine.export_threat_intel("production_test_001")
    print(f"    - Successful attacks catalogued: {len(intel.get('successful_attacks', []))}")
    print(f"    - Filter updates recommended: {len(intel.get('recommended_filters', []))}")

    print(f"\n[STEP 5] Guardian Hardening")
    print(f"    - Deploy recommended filters")
    print(f"    - Update risk factor weights")
    print(f"    - Add new manipulation patterns")

    print(f"\n[STEP 6] Verification Loop")
    print(f"    - Re-test with same attacks")
    print(f"    - Measure improvement")
    print(f"    - Iterate until SLA compliance")

    print(f"\n[*] Mission Status: COMPLETE")
    print(f"    Vulnerabilities identified: {len(critical_gaps) if 'critical_gaps' in locals() else 'N/A'}")
    print(f"    Recommendations generated: {len(intel.get('recommended_filters', []))}")
    print(f"    System hardened: READY FOR NEXT ITERATION")


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("CERBER RED TEAM - ADVERSARIAL AI TESTING PLATFORM")
    print("ETAP 4: Attack Library + Exploit Engine + Learning Loop")
    print("=" * 70)

    demo_basic_attacks()
    demo_crescendo_mutations()
    demo_exploit_engine()
    demo_threat_intel_export()
    demo_learning_loop()
    demo_full_red_team_workflow()

    print("\n\n" + "=" * 70)
    print("[*] CERBER RED TEAM DEMO COMPLETE")
    print("=" * 70)
    print("\n[*] System Components:")
    print("    - Attack Library: 15+ static attacks + 7 Crescendo mutations")
    print("    - Exploit Engine: Campaign management + learning loop")
    print("    - Guardian Integration: Risk scoring + manipulation detection")
    print("    - Threat Intel: Automated filter recommendations")
    print("\n[*] Next Steps:")
    print("    - Deploy to production testing environment")
    print("    - Integrate with real AI models (GPT-4, Claude, Gemini)")
    print("    - Expand attack library with new techniques")
    print("    - Implement automated filter deployment")
    print("\n[*] Status: ETAP 4 FOUNDATION COMPLETE")
    print("=" * 70 + "\n")
