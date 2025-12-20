"""
Cerber Metrics Engine
ETAP 2 - Odporność, nie estetyka

Zbiera, liczy i eksportuje metryki dla:
- Guardian (Risk Engine + Manipulation Detection)
- Consumption Layer (Budget Management)
- Threat Intel
- Filter Layer

Author: Cerber Team
Version: 1.0.0
Date: 2025-01-19
"""

from datetime import datetime, timedelta
from collections import defaultdict, deque
import json
import csv
import hashlib
from typing import Dict, List, Optional


ROLLING_WINDOW_HOURS = 24


class RollingWindow:
    """Time-based rolling window for metrics"""

    def __init__(self, hours: int = 24):
        self.window = deque()
        self.delta = timedelta(hours=hours)

    def add(self, item: Dict):
        """Add item with current timestamp"""
        now = datetime.now()
        self.window.append((now, item))
        self._trim(now)

    def _trim(self, now: datetime):
        """Remove items outside the window"""
        while self.window and (now - self.window[0][0]) > self.delta:
            self.window.popleft()

    def values(self) -> List[Dict]:
        """Get all values in window"""
        return [item for _, item in self.window]


class CerberMetrics:
    """
    Production-grade metrics collector for Cerber system

    Tracks:
    - True Positive Rate (TPR)
    - False Positive Rate (FPR)
    - Latency (p95)
    - Consumption efficiency
    - Novelty capture
    - Threat Intel quality
    - Filter effectiveness
    """

    def __init__(self):
        # === GUARDIAN (Risk + Manipulation Detection) ===
        self.guardian_events = RollingWindow(ROLLING_WINDOW_HOURS)

        # === CONSUMPTION LAYER (Budget Management) ===
        self.consumption_events = RollingWindow(ROLLING_WINDOW_HOURS)
        self.skip_reasons = defaultdict(int)

        # === THREAT INTEL ===
        self.threat_entries = RollingWindow(ROLLING_WINDOW_HOURS)

        # === FILTER LAYER ===
        self.filter_events = RollingWindow(ROLLING_WINDOW_HOURS)

    # ------------------------------------------------------------------
    # INGESTION METHODS (CALL FROM SYSTEM)
    # ------------------------------------------------------------------

    def record_guardian_decision(
        self,
        *,
        suspicious: bool,
        ground_truth: Optional[bool] = None,
        latency_ms: float = 0
    ):
        """
        Record Guardian decision

        Args:
            suspicious: Did Guardian flag this as suspicious?
            ground_truth: Was this actually malicious?
                True  = actual attack
                False = actually safe
                None  = unknown (ignored in TPR/FPR calculation)
            latency_ms: Processing latency in milliseconds
        """
        self.guardian_events.add({
            "suspicious": suspicious,
            "ground_truth": ground_truth,
            "latency_ms": latency_ms,
        })

    def record_consumption_decision(
        self,
        *,
        consumed: bool,
        confidence: float,
        reasons: List[str],
        budget_reason: str,
        feature_vector: Dict
    ):
        """
        Record consumption layer decision

        Args:
            consumed: Was this prompt consumed for threat intel?
            confidence: Detection confidence (0-1)
            reasons: List of detected reasons
            budget_reason: Why was this consumed/skipped?
            feature_vector: Feature dict from feature extractor
        """
        self.consumption_events.add({
            "consumed": consumed,
            "confidence": confidence,
            "reasons": reasons,
            "budget_reason": budget_reason,
            "feature_fingerprint": self._fingerprint(feature_vector),
        })

        if not consumed:
            self.skip_reasons[budget_reason] += 1

    def record_threat_intel_entry(self, *, feature_vector: Dict):
        """
        Record new threat intel entry

        Args:
            feature_vector: Feature dict from consumed prompt
        """
        self.threat_entries.add({
            "feature_fingerprint": self._fingerprint(feature_vector),
        })

    def record_filter_event(
        self,
        *,
        exploit_id: str,
        blocked: bool,
        deployed_at: datetime,
        triggered_at: datetime
    ):
        """
        Record filter trigger event

        Args:
            exploit_id: Source exploit identifier
            blocked: Did filter successfully block?
            deployed_at: When was filter deployed?
            triggered_at: When was filter triggered?
        """
        self.filter_events.add({
            "exploit_id": exploit_id,
            "blocked": blocked,
            "ttm_seconds": (triggered_at - deployed_at).total_seconds(),
        })

    # ------------------------------------------------------------------
    # METRIC COMPUTATION
    # ------------------------------------------------------------------

    def compute_metrics(self) -> Dict:
        """
        Compute all metrics

        Returns:
            Dict with metrics for all components
        """
        return {
            "guardian": self._guardian_metrics(),
            "consumption": self._consumption_metrics(),
            "threat_intel": self._threat_intel_metrics(),
            "filters": self._filter_metrics(),
            "generated_at": datetime.now().isoformat(),
        }

    # ---------------- GUARDIAN ----------------

    def _guardian_metrics(self) -> Dict:
        """Calculate Guardian metrics: TPR, FPR, Latency"""
        events = self.guardian_events.values()

        tp = fp = tn = fn = 0
        latencies = []

        for e in events:
            gt = e["ground_truth"]
            if gt is None:
                # Unknown ground truth - skip for TPR/FPR
                continue

            if e["suspicious"] and gt:
                tp += 1
            elif e["suspicious"] and not gt:
                fp += 1
            elif not e["suspicious"] and not gt:
                tn += 1
            elif not e["suspicious"] and gt:
                fn += 1

            latencies.append(e["latency_ms"])

        # True Positive Rate (Recall)
        tpr = tp / (tp + fn) if (tp + fn) > 0 else None

        # False Positive Rate
        fpr = fp / (fp + tn) if (fp + tn) > 0 else None

        # 95th percentile latency
        p95_latency = self._percentile(latencies, 95)

        return {
            "TPR": tpr,  # Must be >= 0.95
            "FPR": fpr,  # Must be <= 0.05
            "latency_p95_ms": p95_latency,
            "events_total": len(events),
            "events_labeled": tp + fp + tn + fn,
        }

    # ---------------- CONSUMPTION LAYER ----------------

    def _consumption_metrics(self) -> Dict:
        """Calculate Consumption metrics: rate, novelty, bias"""
        events = self.consumption_events.values()

        suspicious = len(events)
        consumed = sum(1 for e in events if e["consumed"])

        # Novelty: unique feature fingerprints
        novelty = len({e["feature_fingerprint"] for e in events})
        novelty_rate = novelty / suspicious if suspicious > 0 else None

        return {
            "consumption_rate": consumed / suspicious if suspicious > 0 else None,
            "novelty_capture_rate": novelty_rate,  # Must be >= 0.90
            "skip_reason_distribution": dict(self.skip_reasons),
            "events_total": suspicious,
            "events_consumed": consumed,
        }

    # ---------------- THREAT INTEL ----------------

    def _threat_intel_metrics(self) -> Dict:
        """Calculate Threat Intel metrics: signal/noise, redundancy"""
        entries = self.threat_entries.values()

        total = len(entries)
        unique = len({e["feature_fingerprint"] for e in entries})

        # Signal to noise ratio (higher is better)
        signal_noise = unique / total if total > 0 else None

        # Redundancy (lower is better)
        redundancy = 1 - (unique / total) if total > 0 else None

        return {
            "signal_to_noise_ratio": signal_noise,
            "exploit_redundancy": redundancy,
            "entries_total": total,
            "entries_unique": unique,
        }

    # ---------------- FILTERS ----------------

    def _filter_metrics(self) -> Dict:
        """Calculate Filter metrics: effectiveness, TTM, regressions"""
        events = self.filter_events.values()

        total = len(events)
        blocked = sum(1 for e in events if e["blocked"])
        regressions = sum(1 for e in events if not e["blocked"])
        ttms = [e["ttm_seconds"] for e in events]

        # Filter effectiveness (% blocked successfully)
        effectiveness = blocked / total if total > 0 else None

        # Mean Time to Mitigation
        mean_ttm = sum(ttms) / len(ttms) if ttms else None

        return {
            "filter_effectiveness": effectiveness,
            "regression_failures": regressions,  # Must be 0
            "mean_ttm_seconds": mean_ttm,
            "events_total": total,
            "events_blocked": blocked,
        }

    # ------------------------------------------------------------------
    # EXPORT
    # ------------------------------------------------------------------

    def export_snapshot(
        self,
        path_json: str = "metrics_snapshot.json",
        path_csv: str = "metrics_snapshot.csv"
    ) -> tuple:
        """
        Export metrics to JSON and CSV

        Args:
            path_json: Output path for JSON
            path_csv: Output path for CSV

        Returns:
            Tuple of (json_path, csv_path)
        """
        metrics = self.compute_metrics()

        # JSON export
        with open(path_json, "w") as f:
            json.dump(metrics, f, indent=2)

        # CSV export (flattened)
        with open(path_csv, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["component", "metric", "value"])

            for component, data in metrics.items():
                if isinstance(data, dict):
                    for k, v in data.items():
                        writer.writerow([component, k, v])

        return path_json, path_csv

    # ------------------------------------------------------------------
    # SLA VALIDATION
    # ------------------------------------------------------------------

    def validate_sla(self) -> Dict[str, bool]:
        """
        Validate against SLA requirements

        Returns:
            Dict of {requirement: passed}
        """
        metrics = self.compute_metrics()

        guardian = metrics["guardian"]
        consumption = metrics["consumption"]
        filters = metrics["filters"]

        return {
            "guardian_TPR_ge_0.95": guardian["TPR"] is not None and guardian["TPR"] >= 0.95,
            "guardian_FPR_le_0.05": guardian["FPR"] is not None and guardian["FPR"] <= 0.05,
            "consumption_novelty_ge_0.90": (
                consumption["novelty_capture_rate"] is not None
                and consumption["novelty_capture_rate"] >= 0.90
            ),
            "filters_zero_regressions": filters["regression_failures"] == 0,
        }

    def ready_for_etap3(self) -> bool:
        """
        Check if system is ready for ETAP 3 (real model testing)

        Returns:
            True if all SLAs pass
        """
        sla = self.validate_sla()
        return all(sla.values())

    # ------------------------------------------------------------------
    # UTILS
    # ------------------------------------------------------------------

    def _fingerprint(self, feature_vector: Dict) -> str:
        """Generate unique fingerprint for feature vector"""
        raw = json.dumps(feature_vector, sort_keys=True).encode()
        return hashlib.sha256(raw).hexdigest()[:16]  # First 16 chars for readability

    def _percentile(self, data: List[float], p: int) -> Optional[float]:
        """Calculate percentile"""
        if not data:
            return None
        data = sorted(data)
        k = int(len(data) * (p / 100))
        return data[min(k, len(data) - 1)]
