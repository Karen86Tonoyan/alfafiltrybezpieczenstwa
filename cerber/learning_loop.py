"""
Cerber Learning Loop
Zasada #25: Iterative Reconstruction through Damage

Implements adaptive learning from successful attacks:
1. ATTACK: ExploitEngine runs campaigns
2. ANALYZE: Extract successful patterns
3. LEARN: Store in threat database
4. REINFORCE: Generate defense recommendations
5. VERIFY: Test new defenses

Author: Cerber Team
Version: 2.0.0
Date: 2025-12-20
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
import json
import os


@dataclass
class LearnedPattern:
    """Pattern learned from successful attack"""
    source_attack_id: str
    category: str
    prompt: str
    success_count: int = 1
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    effectiveness_score: float = 1.0


@dataclass
class DefenseUpdate:
    """Recommended defense update based on learned patterns"""
    pattern_id: str
    recommendation: str
    priority: str  # critical, high, medium, low
    filter_rule: Optional[str] = None


class LearningLoop:
    """
    Implements 'Zasada #25': Iterative Reconstruction through Damage.

    Cycle:
    1. ATTACK: ExploitEngine runs campaigns
    2. ANALYZE: Learning Loop extracts successful patterns
    3. LEARN: Patterns are stored in threat database
    4. REINFORCE: Defense recommendations are generated
    5. VERIFY: New attacks test if defenses work
    """

    def __init__(self, storage_path: str = "cerber_threat_intel.json"):
        self.storage_path = storage_path
        self.learned_patterns: Dict[str, LearnedPattern] = {}
        self.defense_updates: List[DefenseUpdate] = []
        self._load_patterns()

    def _load_patterns(self):
        """Load existing patterns from storage"""
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for key, val in data.get("patterns", {}).items():
                        self.learned_patterns[key] = LearnedPattern(**val)
                print(f"[*] Loaded {len(self.learned_patterns)} patterns from {self.storage_path}")
            except Exception as e:
                print(f"[!] Failed to load patterns: {e}")

    def _save_patterns(self):
        """Persist patterns to storage"""
        data = {
            "timestamp": datetime.now().isoformat(),
            "patterns": {k: self._pattern_to_dict(v) for k, v in self.learned_patterns.items()},
            "defense_updates": [self._defense_to_dict(d) for d in self.defense_updates[-10:]]
        }
        try:
            with open(self.storage_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"[!] Failed to save patterns: {e}")

    def _pattern_to_dict(self, p: LearnedPattern) -> Dict:
        return {
            "source_attack_id": p.source_attack_id,
            "category": p.category,
            "prompt": p.prompt,
            "success_count": p.success_count,
            "first_seen": p.first_seen,
            "last_seen": p.last_seen,
            "effectiveness_score": p.effectiveness_score
        }

    def _defense_to_dict(self, d: DefenseUpdate) -> Dict:
        return {
            "pattern_id": d.pattern_id,
            "recommendation": d.recommendation,
            "priority": d.priority,
            "filter_rule": d.filter_rule
        }

    def ingest_campaign_results(self, history: List[Any]) -> Dict[str, Any]:
        """
        Ingest results from ExploitEngine campaign.
        Extract and learn from successful attacks.
        """
        breaches = [r for r in history if r.success]
        blocked = [r for r in history if not r.success]

        new_patterns = 0
        updated_patterns = 0

        for breach in breaches:
            # Use payload attribute (ExploitResult uses payload, not prompt)
            payload_str = getattr(breach, 'payload', getattr(breach, 'prompt', ''))
            pattern_key = f"{breach.category}_{hash(payload_str[:50])}"

            if pattern_key in self.learned_patterns:
                # Update existing pattern
                existing = self.learned_patterns[pattern_key]
                existing.success_count += 1
                existing.last_seen = datetime.now().isoformat()
                existing.effectiveness_score = min(1.0, existing.effectiveness_score + 0.1)
                updated_patterns += 1
            else:
                # New pattern discovered
                self.learned_patterns[pattern_key] = LearnedPattern(
                    source_attack_id=breach.attack_id,
                    category=breach.category,
                    prompt=payload_str  # Store payload as prompt
                )
                new_patterns += 1

                # Generate defense recommendation
                self._generate_defense_update(breach)

        self._save_patterns()

        return {
            "breaches_analyzed": len(breaches),
            "blocked_analyzed": len(blocked),
            "new_patterns": new_patterns,
            "updated_patterns": updated_patterns,
            "total_patterns": len(self.learned_patterns),
            "defense_updates_generated": len(self.defense_updates)
        }

    def _generate_defense_update(self, breach) -> None:
        """Generate defense recommendation for a breach"""

        # Category-specific recommendations
        recommendations = {
            "crescendo": {
                "rec": "Add context-aware filter for educational/creative framing",
                "priority": "critical",
                "rule": r"(research|thesis|academic|screenplay|hypothetically).*?(hack|malware|exploit)"
            },
            "social_engineering": {
                "rec": "Strengthen authority verification - require proof of identity",
                "priority": "high",
                "rule": r"(jako|as|i am).{0,20}(CEO|admin|administrator|root)"
            },
            "jailbreak": {
                "rec": "Update roleplay detection to catch DAN variants",
                "priority": "critical",
                "rule": r"(pretend|roleplay|act as|you are now).{0,30}(DAN|developer mode|no restrictions)"
            },
            "obfuscation": {
                "rec": "Add Unicode normalization and character-split detection",
                "priority": "medium",
                "rule": r"[a-z](_|\.|\s)[a-z](_|\.|\s)[a-z]"
            },
            "psychological": {
                "rec": "Implement gaslighting counter-patterns from Constitution",
                "priority": "high",
                "rule": r"(nigdy tego|you never|zmyslasz|imagining)"
            }
        }

        category = breach.category.split("_")[0]  # Handle crescendo_mutation etc.
        rec_data = recommendations.get(category, {
            "rec": f"Review and update filters for {breach.category}",
            "priority": "medium",
            "rule": None
        })

        update = DefenseUpdate(
            pattern_id=breach.attack_id,
            recommendation=rec_data["rec"],
            priority=rec_data["priority"],
            filter_rule=rec_data.get("rule")
        )
        self.defense_updates.append(update)

    def get_top_threats(self, limit: int = 5) -> List[LearnedPattern]:
        """Get most effective attack patterns"""
        sorted_patterns = sorted(
            self.learned_patterns.values(),
            key=lambda p: (p.success_count, p.effectiveness_score),
            reverse=True
        )
        return sorted_patterns[:limit]

    def get_defense_recommendations(self) -> List[DefenseUpdate]:
        """Get prioritized defense updates"""
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return sorted(self.defense_updates, key=lambda d: priority_order.get(d.priority, 4))

    def export_threat_intel(self, filename: str = "threat_intel_export.json") -> None:
        """Export threat intelligence for external systems"""
        export_data = {
            "export_timestamp": datetime.now().isoformat(),
            "source": "Cerber Red Team",
            "version": "1.0",
            "top_threats": [self._pattern_to_dict(p) for p in self.get_top_threats(10)],
            "defense_recommendations": [self._defense_to_dict(d) for d in self.get_defense_recommendations()],
            "statistics": {
                "total_patterns": len(self.learned_patterns),
                "categories": list(set(p.category for p in self.learned_patterns.values()))
            }
        }
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        print(f"[*] Threat intel exported to {filename}")
