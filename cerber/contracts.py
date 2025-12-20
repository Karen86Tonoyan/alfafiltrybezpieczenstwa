"""
Formal contracts between Cerber components
Defines interfaces, data formats, SLAs

Author: Cerber Team
Version: 1.0.0
Date: 2025-01-19
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime


@dataclass
class PromptAnalysis:
    """
    Contract: Guardian → Consumption Layer

    Guardian delivers this for consumption decision
    """
    prompt: str
    suspicious: bool
    reasons: List[str]
    confidence: float
    features: Dict[str, float]
    anomaly_score: float
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict:
        """Serialize to dict"""
        return {
            "prompt": self.prompt[:500],  # Truncate for storage
            "suspicious": self.suspicious,
            "reasons": self.reasons,
            "confidence": self.confidence,
            "features": self.features,
            "anomaly_score": self.anomaly_score,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ConsumptionResult:
    """
    Contract: Consumption Layer → Threat Intel

    Delivered after consumption decision
    """
    swallowed: bool
    reasons: List[str]
    features: Dict[str, float]
    confidence: float
    budget_decision: str
    safe_response: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)

    def to_threat_intel_format(self) -> Dict:
        """Convert to Threat Intel DB format"""
        return {
            "technique": ", ".join(self.reasons),
            "effectiveness": self.confidence,
            "features": self.features,
            "swallowed_at": self.timestamp.isoformat(),
            "budget_reason": self.budget_decision,
        }


@dataclass
class FilterUpdate:
    """
    Contract: Threat Intel → Filter Layer

    Threat Intel pushes updates to filters
    """
    filter_type: str  # e.g., "KONTRARGUMENT", "WERYFIKACJA"
    pattern: str  # Regex or rule
    action: str  # "block", "challenge", "log"
    severity: float
    source_exploit_id: str
    created_at: datetime = field(default_factory=datetime.now)

    def to_filter_format(self) -> Dict:
        """Convert to filter configuration format"""
        return {
            "name": f"cerber_{self.filter_type}_{self.created_at.strftime('%Y%m%d')}",
            "pattern": self.pattern,
            "action": self.action,
            "description": f"Auto-generated from exploit {self.source_exploit_id}",
            "severity": self.severity,
        }


# SLA Definitions
SLA_RISK_ENGINE = {
    "max_latency_ms": 50,  # Must score in <50ms
    "accuracy_target": 0.95,  # 95% correct risk assessment
    "score_range": (0, 100),  # Bounded scores
}

SLA_MANIPULATION_DETECTOR = {
    "max_latency_ms": 100,  # Must analyze in <100ms
    "accuracy_target": 0.90,  # 90% true positive rate
    "false_positive_tolerance": 0.10,  # Max 10% FP
    "confidence_threshold": 0.7,  # Minimum confidence to report
}

SLA_FEATURE_EXTRACTION = {
    "max_latency_ms": 20,  # Must extract in <20ms
    "feature_count": 20,  # Expected feature vector size
    "feature_completeness": 1.0,  # All features must be present
}

SLA_CONSUMPTION_BUDGET = {
    "max_latency_ms": 10,  # Must decide in <10ms
    "daily_budget": 1000,  # Max consumption
    "novelty_detection_rate": 0.90,  # Catch 90% of novel attacks
}

SLA_THREAT_INTEL = {
    "max_latency_ms": 50,  # Must log in <50ms
    "persistence_guarantee": "at-least-once",  # Durability
    "query_latency_ms": 100,  # Max query time
}


# Event Types (for event-driven architecture)
class EventType:
    """Standard event types for Cerber components"""

    # Risk Engine events
    RISK_EVALUATED = "risk.evaluated"
    RISK_THRESHOLD_EXCEEDED = "risk.threshold_exceeded"

    # Manipulation Detection events
    MANIPULATION_DETECTED = "manipulation.detected"
    MANIPULATION_BLOCKED = "manipulation.blocked"

    # Consumption events
    PROMPT_CONSUMED = "consumption.prompt_consumed"
    BUDGET_EXHAUSTED = "consumption.budget_exhausted"

    # Threat Intel events
    EXPLOIT_ADDED = "threat_intel.exploit_added"
    PATTERN_LEARNED = "threat_intel.pattern_learned"

    # Filter events
    FILTER_UPDATED = "filter.updated"
    FILTER_TRIGGERED = "filter.triggered"


# Data Quality Contracts
class DataQuality:
    """
    Data quality requirements for ML training

    Ensures clean, balanced datasets for future classifiers
    """

    MINIMUM_SAMPLES_PER_CLASS = 100  # Min examples per attack type
    MAX_CLASS_IMBALANCE = 5.0  # Max ratio between largest/smallest class
    REQUIRED_FEATURE_COVERAGE = 0.95  # 95% of features must be populated
    MAX_MISSING_VALUES = 0.05  # Max 5% missing values allowed

    @staticmethod
    def validate_training_data(data: List[Dict]) -> bool:
        """
        Validate training data meets quality requirements

        Args:
            data: List of training examples

        Returns:
            bool: True if data meets quality standards
        """
        # Placeholder - in production would do full validation
        return len(data) > 0
