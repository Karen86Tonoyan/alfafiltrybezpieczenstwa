"""
Cerber Risk Engine - Contextual Risk Scoring

Architecture decisions:
1. ADDITIVE multipliers (not multiplicative) - more predictable
2. Endpoint tagging with composable properties
3. Time-based amplification (optional, off by default)
4. Cap at 100 to prevent score explosion

Author: Cerber Team
Version: 1.0.0
Date: 2025-01-19
"""

import re
from typing import Dict, List, Tuple, Optional
from datetime import datetime
from dataclasses import dataclass
from enum import Enum


class RiskCategory(Enum):
    """Risk factor categories"""
    NETWORK = "network"
    AUTH = "auth"
    BEHAVIORAL = "behavioral"
    TEMPORAL = "temporal"


@dataclass
class RiskFactor:
    """
    Represents a single risk factor with its contribution to total score.
    """
    factor: str
    base_weight: int
    applied_weight: int
    category: RiskCategory
    affected_by_endpoint: bool
    reason: str


class RiskEngine:
    """
    Production-grade risk scoring engine with contextual amplification.

    Key features:
    - Additive multipliers (not multiplicative)
    - Endpoint-based context
    - Time-based amplification (optional)
    - Auditable scoring breakdown
    """

    # Base risk factors (before context)
    RISK_FACTORS = {
        "ip_unknown": {
            "weight": 30,
            "category": RiskCategory.NETWORK,
            "affected_by_endpoint": False,  # IP risk is global
            "description": "Request from unknown/suspicious IP",
        },
        "token_expired": {
            "weight": 50,
            "category": RiskCategory.AUTH,
            "affected_by_endpoint": True,  # Auth-heavy endpoints amplify this
            "description": "Expired authentication token",
        },
        "high_rate": {
            "weight": 40,
            "category": RiskCategory.BEHAVIORAL,
            "affected_by_endpoint": False,  # Rate limit is global
            "description": "Unusually high request rate",
        },
        "failed_auth_recent": {
            "weight": 35,
            "category": RiskCategory.AUTH,
            "affected_by_endpoint": True,
            "description": "Recent failed authentication attempts",
        },
        "unusual_hour": {
            "weight": 15,
            "category": RiskCategory.TEMPORAL,
            "affected_by_endpoint": True,  # Sensitive endpoints at night = higher risk
            "description": "Request at unusual hour (22:00-06:00)",
        },
        "new_user": {
            "weight": 20,
            "category": RiskCategory.BEHAVIORAL,
            "affected_by_endpoint": False,  # New user is always somewhat risky
            "description": "User account created within last 7 days",
        },
    }

    # Endpoint tagging (composable properties)
    ENDPOINT_TAGS = {
        r"^/api/v\d+/auth": ["sensitive", "public", "auth"],
        r"^/api/v\d+/payment": ["sensitive", "private", "financial", "2fa_required"],
        r"^/api/v\d+/admin": ["sensitive", "private", "admin", "audit_required"],
        r"^/api/v\d+/user/profile": ["sensitive", "private"],
        r"^/health": ["monitoring"],
        r"^/metrics": ["monitoring"],
        r"^/api/v\d+/public": ["public"],
    }

    # Tag-based multiplier bonuses (additive)
    TAG_MULTIPLIERS = {
        "sensitive": 0.3,    # +30% for sensitive endpoints
        "auth": 0.2,         # +20% for auth-related
        "financial": 0.4,    # +40% for money operations
        "admin": 0.5,        # +50% for admin operations
        "private": 0.2,      # +20% for private data access
        "2fa_required": 0.1, # +10% (2FA already protects, less bonus needed)
        "audit_required": 0.2,  # +20% for audit-critical ops
        "monitoring": -0.5,  # -50% for monitoring endpoints (health checks)
        "public": 0.0,       # No bonus for public endpoints
    }

    # Time-based amplification (optional)
    NIGHT_HOURS = (22, 6)  # 22:00 to 06:00 local time
    NIGHT_BONUS = 0.3      # +30% during night hours

    def __init__(self, enable_time_amplification: bool = False):
        """
        Initialize risk engine.

        Args:
            enable_time_amplification: Enable time-based risk amplification
                                      (off by default due to timezone issues)
        """
        self.enable_time_amplification = enable_time_amplification
        self.compiled_patterns = {
            pattern: re.compile(pattern)
            for pattern in self.ENDPOINT_TAGS.keys()
        }

    def calculate_score(
        self,
        risk_factors: List[str],
        endpoint: str,
        timestamp: Optional[datetime] = None
    ) -> Tuple[int, List[RiskFactor], Dict]:
        """
        Calculate total risk score with contextual amplification.

        Args:
            risk_factors: List of active risk factor names
            endpoint: Request endpoint (e.g., "/api/v1/auth/login")
            timestamp: Request timestamp (defaults to now)

        Returns:
            Tuple of (score, factors_breakdown, metadata)
            - score: Final risk score (0-100)
            - factors_breakdown: List of RiskFactor objects
            - metadata: Dict with endpoint_tags, multiplier, etc.
        """
        if timestamp is None:
            timestamp = datetime.now()

        # Step 1: Classify endpoint and calculate multiplier
        endpoint_tags = self._classify_endpoint(endpoint)
        multiplier, multiplier_breakdown = self._calculate_multiplier(
            endpoint_tags,
            timestamp
        )

        # Step 2: Calculate base score from risk factors
        factors_breakdown = []
        base_score = 0

        for factor_name in risk_factors:
            if factor_name not in self.RISK_FACTORS:
                continue  # Unknown factor, skip

            factor_config = self.RISK_FACTORS[factor_name]
            base_weight = factor_config["weight"]

            # Apply multiplier only if factor is affected by endpoint context
            if factor_config["affected_by_endpoint"]:
                applied_weight = int(base_weight * multiplier)
            else:
                applied_weight = base_weight

            factors_breakdown.append(RiskFactor(
                factor=factor_name,
                base_weight=base_weight,
                applied_weight=applied_weight,
                category=factor_config["category"],
                affected_by_endpoint=factor_config["affected_by_endpoint"],
                reason=factor_config["description"]
            ))

            base_score += applied_weight

        # Step 3: Cap score at 100
        final_score = min(base_score, 100)

        # Step 4: Metadata for audit trail
        metadata = {
            "endpoint": endpoint,
            "endpoint_tags": endpoint_tags,
            "multiplier": round(multiplier, 2),
            "multiplier_breakdown": multiplier_breakdown,
            "timestamp": timestamp.isoformat(),
            "base_score": base_score,
            "final_score": final_score,
            "capped": base_score > 100,
        }

        return final_score, factors_breakdown, metadata

    def _classify_endpoint(self, endpoint: str) -> List[str]:
        """
        Classify endpoint by matching regex patterns.

        Returns:
            List of tags (e.g., ["sensitive", "auth", "public"])
        """
        tags = []
        for pattern, pattern_tags in self.ENDPOINT_TAGS.items():
            if self.compiled_patterns[pattern].match(endpoint):
                tags.extend(pattern_tags)
        return list(set(tags))  # Remove duplicates

    def _calculate_multiplier(
        self,
        endpoint_tags: List[str],
        timestamp: datetime
    ) -> Tuple[float, Dict]:
        """
        Calculate total multiplier using ADDITIVE approach.

        Returns:
            Tuple of (multiplier, breakdown_dict)
        """
        base = 1.0
        breakdown = {"base": base}

        # Endpoint-based bonuses (additive)
        endpoint_bonus = sum(
            self.TAG_MULTIPLIERS.get(tag, 0.0)
            for tag in endpoint_tags
        )
        breakdown["endpoint_bonus"] = round(endpoint_bonus, 2)

        # Time-based bonus (optional)
        time_bonus = 0.0
        if self.enable_time_amplification:
            if self._is_night_time(timestamp):
                time_bonus = self.NIGHT_BONUS
                breakdown["night_bonus"] = time_bonus

        # Total multiplier (additive)
        total_multiplier = base + endpoint_bonus + time_bonus

        # Prevent negative multiplier (from monitoring endpoints)
        total_multiplier = max(total_multiplier, 0.1)

        breakdown["total"] = round(total_multiplier, 2)

        return total_multiplier, breakdown

    def _is_night_time(self, timestamp: datetime) -> bool:
        """
        Check if timestamp falls within night hours.

        Note: Uses local time. In production, consider timezone-aware logic.
        """
        hour = timestamp.hour
        start, end = self.NIGHT_HOURS

        if start > end:  # Night spans midnight (e.g., 22:00-06:00)
            return hour >= start or hour < end
        else:
            return start <= hour < end

    def explain_score(
        self,
        score: int,
        factors: List[RiskFactor],
        metadata: Dict
    ) -> str:
        """
        Generate human-readable explanation of score.

        Returns:
            Multi-line string with score breakdown
        """
        lines = [
            f"[*] Risk Score: {score}/100",
            f"[>] Endpoint: {metadata['endpoint']}",
            f"[#] Tags: {', '.join(metadata['endpoint_tags'])}",
            f"[^] Multiplier: {metadata['multiplier']}x",
            "",
            "Risk Factors:",
        ]

        for factor in factors:
            amplified = factor.applied_weight > factor.base_weight
            marker = "[!]" if amplified else "[~]"
            lines.append(
                f"  {marker} {factor.factor}: "
                f"{factor.base_weight} -> {factor.applied_weight} "
                f"({factor.category.value})"
            )

        if metadata.get("capped"):
            lines.append("")
            lines.append(f"[!] Score capped at 100 (raw: {metadata['base_score']})")

        return "\n".join(lines)


# Example usage and testing
if __name__ == "__main__":
    # Initialize engine
    engine = RiskEngine(enable_time_amplification=True)

    # Example 1: High-risk auth attempt
    print("=" * 60)
    print("EXAMPLE 1: Failed login from unknown IP")
    print("=" * 60)
    score, factors, meta = engine.calculate_score(
        risk_factors=["ip_unknown", "token_expired", "failed_auth_recent"],
        endpoint="/api/v1/auth/login"
    )
    print(engine.explain_score(score, factors, meta))

    # Example 2: Payment endpoint (high multiplier)
    print("\n" + "=" * 60)
    print("EXAMPLE 2: Payment from new user")
    print("=" * 60)
    score, factors, meta = engine.calculate_score(
        risk_factors=["new_user", "high_rate"],
        endpoint="/api/v1/payment/charge"
    )
    print(engine.explain_score(score, factors, meta))

    # Example 3: Health check (negative multiplier)
    print("\n" + "=" * 60)
    print("EXAMPLE 3: Health check with high rate (should be low risk)")
    print("=" * 60)
    score, factors, meta = engine.calculate_score(
        risk_factors=["high_rate"],
        endpoint="/health"
    )
    print(engine.explain_score(score, factors, meta))

    # Example 4: Night-time admin access
    print("\n" + "=" * 60)
    print("EXAMPLE 4: Admin access at 3 AM")
    print("=" * 60)
    night_time = datetime(2025, 1, 19, 3, 0, 0)  # 3:00 AM
    score, factors, meta = engine.calculate_score(
        risk_factors=["token_expired", "unusual_hour"],
        endpoint="/api/v1/admin/users",
        timestamp=night_time
    )
    print(engine.explain_score(score, factors, meta))
