"""
Cerber Kafka Producer
Event Publisher for Risk and Manipulation Events

Publishes events to Kafka topics for Guardian consumption.
Partitioned by endpoint for scalable processing.

Author: Cerber Team
Version: 2.0.0
Date: 2025-12-20
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from datetime import datetime
import json

# Kafka import with fallback
try:
    from kafka import KafkaProducer
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False
    print("[WARN] kafka-python not installed. Events will be logged only.")


@dataclass
class RiskEvent:
    """Risk evaluation event structure"""
    event_type: str = "risk.evaluated"
    timestamp: str = None
    endpoint: str = ""
    user_id: str = "anon"
    score: int = 0
    multiplier: float = 1.0
    decision: str = "allow"
    reasons: List[dict] = field(default_factory=list)

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict:
        return {
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "endpoint": self.endpoint,
            "user_id": self.user_id,
            "score": self.score,
            "multiplier": self.multiplier,
            "decision": self.decision,
            "reasons": self.reasons
        }


@dataclass
class ManipulationEvent:
    """Manipulation detection event structure"""
    event_type: str = "manipulation.detected"
    timestamp: str = None
    endpoint: str = ""
    user_id: str = "anon"
    manipulation_type: str = ""
    confidence: float = 0.0
    evidence: str = ""
    constitutional_response: str = ""

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict:
        return {
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "endpoint": self.endpoint,
            "user_id": self.user_id,
            "manipulation_type": self.manipulation_type,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "constitutional_response": self.constitutional_response
        }


class CerberKafkaProducer:
    """
    Kafka producer for Cerber events

    Publishes to 'cerber.risk_events' topic with endpoint-based partitioning
    """

    def __init__(self, bootstrap_servers: List[str] = None):
        """
        Initialize Kafka producer

        Args:
            bootstrap_servers: List of Kafka broker addresses
        """
        self.bootstrap_servers = bootstrap_servers or ['localhost:9092']
        self.producer = None

        if KAFKA_AVAILABLE:
            try:
                self.producer = KafkaProducer(
                    bootstrap_servers=self.bootstrap_servers,
                    value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                    key_serializer=lambda k: k.encode('utf-8') if k else None
                )
                print(f"[*] Kafka Producer initialized: {self.bootstrap_servers}")
            except Exception as e:
                print(f"[ERROR] Failed to initialize Kafka producer: {e}")
                self.producer = None
        else:
            print("[WARN] Kafka not available - events will only be logged")

    def publish_risk_event(self, ctx: Dict[str, Any], score: int, reasons: List, multiplier: float):
        """
        Publish risk evaluation event

        Args:
            ctx: Request context (endpoint, user_id, etc.)
            score: Risk score (0-100)
            reasons: List of risk factors detected
            multiplier: Applied multiplier
        """
        # Determine decision based on score
        if score < 30:
            decision = "allow"
        elif score < 70:
            decision = "challenge"
        else:
            decision = "block"

        # Create event
        event = RiskEvent(
            endpoint=ctx.get("endpoint", ""),
            user_id=ctx.get("user_id", "anon"),
            score=score,
            multiplier=multiplier,
            decision=decision,
            reasons=[{"factor": getattr(r, 'factor', str(r)),
                      "weight": getattr(r, 'applied_weight', 0)}
                     for r in reasons]
        )

        # Publish or log
        if self.producer:
            try:
                self.producer.send(
                    'cerber.risk_events',
                    value=event.to_dict(),
                    key=event.endpoint or "unknown"
                )
                self.producer.flush()
                print(f"[Kafka] Published risk event: {event.endpoint} score={score}")
            except Exception as e:
                print(f"[ERROR] Failed to publish risk event: {e}")
        else:
            print(f"[LOG] RiskEvent: {event.to_dict()}")

    def publish_manipulation_event(self, endpoint: str, user_id: str, result: Dict):
        """
        Publish manipulation detection event

        Args:
            endpoint: API endpoint
            user_id: User identifier
            result: Detection result from ManipulationDetector
        """
        event = ManipulationEvent(
            endpoint=endpoint,
            user_id=str(user_id),
            manipulation_type=result.get("manipulation_type", ""),
            confidence=result.get("confidence", 0.0),
            evidence=result.get("evidence", ""),
            constitutional_response=result.get("constitutional_response", "")
        )

        # Publish or log
        if self.producer:
            try:
                self.producer.send(
                    'cerber.risk_events',
                    value=event.to_dict(),
                    key=endpoint or "unknown"
                )
                self.producer.flush()
                print(f"[Kafka] Published manipulation event: {event.manipulation_type} conf={event.confidence:.2f}")
            except Exception as e:
                print(f"[ERROR] Failed to publish manipulation event: {e}")
        else:
            print(f"[LOG] ManipulationEvent: {event.to_dict()}")

    def close(self):
        """Close producer connection"""
        if self.producer:
            self.producer.flush()
            self.producer.close()
            print("[*] Kafka Producer closed")


# Global producer instance (singleton pattern)
_global_producer = None


def get_producer() -> CerberKafkaProducer:
    """Get or create global producer instance"""
    global _global_producer
    if _global_producer is None:
        _global_producer = CerberKafkaProducer()
    return _global_producer


def publish_risk_event(ctx: Dict[str, Any], score: int, reasons: List, multiplier: float):
    """Convenience function for publishing risk events"""
    producer = get_producer()
    producer.publish_risk_event(ctx, score, reasons, multiplier)


def publish_manipulation_event(endpoint: str, user_id: str, result: Dict):
    """Convenience function for publishing manipulation events"""
    producer = get_producer()
    producer.publish_manipulation_event(endpoint, user_id, result)
