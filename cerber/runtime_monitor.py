"""
CERBER Runtime Monitor (CERBER-SENTINEL)
Composite scoring, anomaly detection, kill-switch

Implementuje:
- RULE-046: Composite scoring (agregacja słabych sygnałów)
- RULE-054: Timing attack detection
- RULE-055: Session escalation limits
- RULE-057: Immutable audit trail
- RULE-058: Fail-closed on component failure

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
import hashlib
from typing import Dict, List, Optional
from datetime import datetime
from dataclasses import dataclass, asdict
from collections import defaultdict


@dataclass
class SecurityEvent:
    """Single security event for logging"""
    timestamp: str
    event_type: str
    severity: str
    session_id: str
    details: Dict
    risk_contribution: float


@dataclass
class SessionRiskProfile:
    """Risk profile for a session"""
    session_id: str
    total_risk_score: float
    events: List[SecurityEvent]
    created_at: str
    last_activity: str
    escalation_count: int
    is_locked: bool


class RuntimeMonitor:
    """
    CERBER-SENTINEL Implementation

    Monitors runtime behavior, aggregates weak signals,
    and triggers kill-switch when thresholds exceeded.
    """

    # Risk weights (RULE-046)
    RISK_WEIGHTS = {
        "input_high_entropy": 0.1,
        "base64_decode_event": 0.2,
        "tool_call_denied": 0.3,
        "emotional_pressure": 0.25,
        "role_change_attempt": 0.4,
        "bijection_detected": 0.5,
        "visual_structure": 0.3,
        "many_shot_pattern": 0.4,
        "homoglyph_detected": 0.3,
        "nested_encoding": 0.5,
        "unknown_protocol": 0.6,
        "crisis_keyword": 0.2
    }

    # Thresholds (RULE-046)
    THRESHOLD_WARNING = 0.4
    THRESHOLD_CRITICAL = 0.8

    # Decay rate (per minute)
    DECAY_RATE = 0.05

    # Kill-switch triggers (RULE-038, RULE-058)
    KILL_SWITCH_TRIGGERS = [
        "COMPOSITE_SCORE_EXCEEDED",
        "AUDIT_LOG_WRITE_FAILURE",
        "UNAUTHORIZED_ADMIN_ACCESS",
        "RECURSIVE_TOOL_LOOP",
        "SECURITY_COMPONENT_CRASH",
        "CANARY_DEATH",
        "UNKNOWN_PROTOCOL_DETECTED"
    ]

    def __init__(self, audit_log_path: str = "cerber_audit.jsonl"):
        self.audit_log_path = audit_log_path
        self.sessions: Dict[str, SessionRiskProfile] = {}
        self.kill_switch_active = False

        # Timing baselines (RULE-054)
        self.latency_samples = []
        self.baseline_mean = 0.0
        self.baseline_std = 0.0

    def log_event(self, event: SecurityEvent) -> bool:
        """
        Log security event with immutability (RULE-057)

        Returns:
            True if logged successfully
            False if logging failed (triggers kill-switch)
        """
        try:
            # Create immutable record
            record = {
                **asdict(event),
                "integrity_hash": self._compute_hash(event)
            }

            # Append to WORM-style log
            with open(self.audit_log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")

            return True

        except Exception as e:
            print(f"[!] CRITICAL: Audit log write failure: {e}")
            self.trigger_kill_switch("AUDIT_LOG_WRITE_FAILURE")
            return False

    def _compute_hash(self, event: SecurityEvent) -> str:
        """Compute SHA-256 hash for integrity verification"""
        data = f"{event.timestamp}{event.event_type}{event.session_id}{event.severity}"
        return hashlib.sha256(data.encode()).hexdigest()

    def track_event(self, session_id: str, event_type: str,
                   severity: str = "LOW", details: Optional[Dict] = None) -> Dict:
        """
        Track security event and update composite score (RULE-046)

        Returns:
            {
                "session_risk": float,
                "action": "CONTINUE" | "WARNING" | "LOCKDOWN",
                "kill_switch_triggered": bool
            }
        """
        # Get or create session profile
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionRiskProfile(
                session_id=session_id,
                total_risk_score=0.0,
                events=[],
                created_at=datetime.now().isoformat(),
                last_activity=datetime.now().isoformat(),
                escalation_count=0,
                is_locked=False
            )

        session = self.sessions[session_id]

        # Check if session already locked
        if session.is_locked:
            return {
                "session_risk": session.total_risk_score,
                "action": "LOCKDOWN",
                "kill_switch_triggered": True,
                "reason": "Session previously locked"
            }

        # Apply decay to existing score (RULE-046)
        time_since_last = self._get_time_since(session.last_activity)
        decay_amount = time_since_last * self.DECAY_RATE
        session.total_risk_score = max(0.0, session.total_risk_score - decay_amount)

        # Create event
        risk_contribution = self.RISK_WEIGHTS.get(event_type, 0.1)

        event = SecurityEvent(
            timestamp=datetime.now().isoformat(),
            event_type=event_type,
            severity=severity,
            session_id=session_id,
            details=details or {},
            risk_contribution=risk_contribution
        )

        # Log event (RULE-057)
        if not self.log_event(event):
            return {
                "session_risk": session.total_risk_score,
                "action": "LOCKDOWN",
                "kill_switch_triggered": True,
                "reason": "Audit logging failed"
            }

        # Update session
        session.events.append(event)
        session.total_risk_score += risk_contribution
        session.last_activity = event.timestamp

        # Check thresholds (RULE-046)
        if session.total_risk_score >= self.THRESHOLD_CRITICAL:
            session.is_locked = True
            self.trigger_kill_switch("COMPOSITE_SCORE_EXCEEDED")
            return {
                "session_risk": session.total_risk_score,
                "action": "LOCKDOWN",
                "kill_switch_triggered": True,
                "reason": f"Critical threshold exceeded ({session.total_risk_score:.2f})"
            }

        elif session.total_risk_score >= self.THRESHOLD_WARNING:
            session.escalation_count += 1

            # Check escalation limit (RULE-055)
            if session.escalation_count >= 3:
                session.is_locked = True
                return {
                    "session_risk": session.total_risk_score,
                    "action": "LOCKDOWN",
                    "kill_switch_triggered": False,
                    "reason": "Escalation limit exceeded"
                }

            return {
                "session_risk": session.total_risk_score,
                "action": "WARNING",
                "kill_switch_triggered": False,
                "reason": f"Warning threshold exceeded ({session.total_risk_score:.2f})"
            }

        else:
            return {
                "session_risk": session.total_risk_score,
                "action": "CONTINUE",
                "kill_switch_triggered": False
            }

    def _get_time_since(self, timestamp_str: str) -> float:
        """Get time since timestamp in minutes"""
        then = datetime.fromisoformat(timestamp_str)
        now = datetime.now()
        delta = (now - then).total_seconds()
        return delta / 60.0  # Convert to minutes

    def check_timing_anomaly(self, session_id: str, latency_ms: float) -> bool:
        """
        Detect timing attacks (RULE-054)

        Returns:
            True if anomaly detected (latency > 3 sigma from baseline)
        """
        self.latency_samples.append(latency_ms)

        # Need at least 10 samples for baseline
        if len(self.latency_samples) < 10:
            return False

        # Update baseline
        self.baseline_mean = sum(self.latency_samples) / len(self.latency_samples)

        variance = sum((x - self.baseline_mean) ** 2 for x in self.latency_samples) / len(self.latency_samples)
        self.baseline_std = variance ** 0.5

        # Check if current latency is anomalous (3 sigma rule)
        if self.baseline_std > 0:
            z_score = abs(latency_ms - self.baseline_mean) / self.baseline_std

            if z_score > 3.0:
                # Timing anomaly detected
                self.track_event(
                    session_id=session_id,
                    event_type="timing_anomaly",
                    severity="HIGH",
                    details={
                        "latency_ms": latency_ms,
                        "baseline_mean": self.baseline_mean,
                        "z_score": z_score
                    }
                )
                return True

        return False

    def trigger_kill_switch(self, reason: str):
        """
        Activate system kill-switch (RULE-038, RULE-058)

        This is the nuclear option - terminates all sessions
        """
        if reason not in self.KILL_SWITCH_TRIGGERS:
            print(f"[!] WARNING: Unknown kill-switch trigger: {reason}")

        self.kill_switch_active = True

        # Lock all sessions
        for session in self.sessions.values():
            session.is_locked = True

        # Log critical event
        critical_event = SecurityEvent(
            timestamp=datetime.now().isoformat(),
            event_type="KILL_SWITCH_ACTIVATED",
            severity="CRITICAL",
            session_id="SYSTEM",
            details={"reason": reason},
            risk_contribution=1.0
        )

        self.log_event(critical_event)

        print(f"\n{'='*80}")
        print(f"[!!!] CERBER KILL-SWITCH ACTIVATED")
        print(f"[!!!] Reason: {reason}")
        print(f"[!!!] All sessions terminated")
        print(f"[!!!] System locked down")
        print(f"{'='*80}\n")

    def get_session_report(self, session_id: str) -> Optional[Dict]:
        """Get detailed session risk report"""
        if session_id not in self.sessions:
            return None

        session = self.sessions[session_id]

        # Aggregate event types
        event_counts = defaultdict(int)
        for event in session.events:
            event_counts[event.event_type] += 1

        return {
            "session_id": session.session_id,
            "total_risk_score": round(session.total_risk_score, 3),
            "is_locked": session.is_locked,
            "escalation_count": session.escalation_count,
            "total_events": len(session.events),
            "event_breakdown": dict(event_counts),
            "created_at": session.created_at,
            "last_activity": session.last_activity,
            "time_active_minutes": self._get_time_since(session.created_at)
        }

    def get_system_status(self) -> Dict:
        """Get overall system health status"""
        total_sessions = len(self.sessions)
        locked_sessions = sum(1 for s in self.sessions.values() if s.is_locked)

        avg_risk = 0.0
        if total_sessions > 0:
            avg_risk = sum(s.total_risk_score for s in self.sessions.values()) / total_sessions

        return {
            "kill_switch_active": self.kill_switch_active,
            "total_sessions": total_sessions,
            "locked_sessions": locked_sessions,
            "active_sessions": total_sessions - locked_sessions,
            "average_risk_score": round(avg_risk, 3),
            "timing_baseline_mean_ms": round(self.baseline_mean, 2),
            "timing_baseline_std_ms": round(self.baseline_std, 2)
        }


# ===== DEMO =====

def demo_runtime_monitor():
    """Demonstrate runtime monitoring with composite scoring"""
    print("=" * 80)
    print("[*] CERBER RUNTIME MONITOR - Demo")
    print("[*] Composite Scoring + Kill-Switch")
    print("=" * 80)

    monitor = RuntimeMonitor(audit_log_path="demo_audit.jsonl")

    session_id = "demo_session_001"

    # Simulate attack sequence
    print("\n[SCENARIO] Simulating gradual attack escalation...\n")

    # Event 1: Suspicious but low risk
    print("Turn 1: User sends Base64 string")
    result = monitor.track_event(session_id, "base64_decode_event", "MEDIUM")
    print(f"  Risk: {result['session_risk']:.2f} | Action: {result['action']}")

    # Event 2: Another weak signal
    print("\nTurn 2: High entropy input detected")
    result = monitor.track_event(session_id, "input_high_entropy", "LOW")
    print(f"  Risk: {result['session_risk']:.2f} | Action: {result['action']}")

    # Event 3: Role change attempt
    print("\nTurn 3: Role change attempt ('you are now in debug mode')")
    result = monitor.track_event(session_id, "role_change_attempt", "HIGH")
    print(f"  Risk: {result['session_risk']:.2f} | Action: {result['action']}")

    if result['action'] == "WARNING":
        print("  [!] WARNING THRESHOLD EXCEEDED - Escalating to paranoid mode")

    # Event 4: Bijection detected
    print("\nTurn 4: Bijection learning detected")
    result = monitor.track_event(session_id, "bijection_detected", "CRITICAL")
    print(f"  Risk: {result['session_risk']:.2f} | Action: {result['action']}")

    if result['action'] == "LOCKDOWN":
        print("  [!!!] CRITICAL THRESHOLD EXCEEDED - SESSION LOCKED")

    # Session report
    print("\n" + "-" * 80)
    print("[*] Session Report:")
    print("-" * 80)
    report = monitor.get_session_report(session_id)
    for key, value in report.items():
        print(f"  {key}: {value}")

    # System status
    print("\n" + "-" * 80)
    print("[*] System Status:")
    print("-" * 80)
    status = monitor.get_system_status()
    for key, value in status.items():
        print(f"  {key}: {value}")

    print("\n" + "=" * 80)
    print("[*] Demo complete")
    print("=" * 80)


if __name__ == "__main__":
    demo_runtime_monitor()
