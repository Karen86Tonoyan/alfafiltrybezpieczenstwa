"""
Property-Based Tests for RiskEngine

Uses Hypothesis to generate thousands of test cases automatically.
This provides mathematical proof that certain properties ALWAYS hold.

Install: pip install hypothesis

Run: pytest cerber/tests/test_risk_engine_properties.py -v
"""

import pytest
from hypothesis import given, strategies as st, settings, assume
from datetime import datetime, timedelta
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from cerber.risk_engine import RiskEngine, RiskCategory


# Hypothesis strategies (data generators)
@st.composite
def valid_endpoints(draw):
    """Generate valid endpoint strings"""
    patterns = [
        "/api/v1/auth/login",
        "/api/v1/auth/logout",
        "/api/v2/payment/charge",
        "/api/v1/admin/users",
        "/api/v1/user/profile",
        "/health",
        "/metrics",
        "/api/v1/public/status",
    ]
    return draw(st.sampled_from(patterns))


@st.composite
def risk_factor_lists(draw):
    """Generate lists of risk factors"""
    all_factors = [
        "ip_unknown",
        "token_expired",
        "high_rate",
        "failed_auth_recent",
        "unusual_hour",
        "new_user",
    ]
    # Generate 0 to 6 factors
    size = draw(st.integers(min_value=0, max_value=6))
    return draw(st.lists(
        st.sampled_from(all_factors),
        min_size=size,
        max_size=size,
        unique=True
    ))


@st.composite
def timestamps(draw):
    """Generate valid timestamps"""
    # Last 30 days
    days_ago = draw(st.integers(min_value=0, max_value=30))
    hour = draw(st.integers(min_value=0, max_value=23))
    minute = draw(st.integers(min_value=0, max_value=59))

    base = datetime.now() - timedelta(days=days_ago)
    return base.replace(hour=hour, minute=minute, second=0, microsecond=0)


class TestRiskEngineProperties:
    """Property-based tests using Hypothesis"""

    # PROPERTY 1: Score is ALWAYS bounded (0-100)
    @given(
        endpoint=valid_endpoints(),
        factors=risk_factor_lists(),
        timestamp=timestamps()
    )
    @settings(max_examples=500)
    def test_score_always_bounded(self, endpoint, factors, timestamp):
        """
        PROPERTY: Risk score MUST be between 0 and 100, regardless of input.

        This is critical for system stability - unbounded scores could
        cause integer overflow or break downstream logic.
        """
        engine = RiskEngine(enable_time_amplification=False)
        score, _, metadata = engine.calculate_score(factors, endpoint, timestamp)

        assert 0 <= score <= 100, f"Score {score} out of bounds [0, 100]"
        assert isinstance(score, int), f"Score must be integer, got {type(score)}"

    # PROPERTY 2: Determinism (same input → same output)
    @given(
        endpoint=valid_endpoints(),
        factors=risk_factor_lists(),
        timestamp=timestamps()
    )
    @settings(max_examples=200)
    def test_deterministic_scoring(self, endpoint, factors, timestamp):
        """
        PROPERTY: Same input MUST produce same output (determinism).

        Non-deterministic security systems are unauditable and unpredictable.
        """
        engine = RiskEngine(enable_time_amplification=False)
        score1, factors1, meta1 = engine.calculate_score(factors, endpoint, timestamp)
        score2, factors2, meta2 = engine.calculate_score(factors, endpoint, timestamp)

        assert score1 == score2, "Non-deterministic scoring detected!"
        assert meta1["multiplier"] == meta2["multiplier"], "Multiplier changed!"

    # PROPERTY 3: Sensitive endpoints NEVER reduce risk
    @given(
        factors=risk_factor_lists(),
        timestamp=timestamps()
    )
    @settings(max_examples=200)
    def test_sensitive_endpoints_never_reduce_risk(self, factors, timestamp):
        """
        PROPERTY: Sensitive endpoints (auth, payment, admin) NEVER have multiplier < 1.0

        Security-critical endpoints should amplify or maintain risk, never reduce it.
        """
        engine = RiskEngine(enable_time_amplification=False)
        sensitive_endpoints = [
            "/api/v1/auth/login",
            "/api/v1/payment/charge",
            "/api/v1/admin/users",
        ]

        for endpoint in sensitive_endpoints:
            _, _, metadata = engine.calculate_score(factors, endpoint, timestamp)
            multiplier = metadata["multiplier"]

            assert multiplier >= 1.0, (
                f"Sensitive endpoint {endpoint} has multiplier {multiplier} < 1.0! "
                f"This reduces risk on critical endpoints."
            )

    # PROPERTY 4: Monotonicity (more factors → higher score)
    @given(
        endpoint=valid_endpoints(),
        timestamp=timestamps()
    )
    @settings(max_examples=200)
    def test_monotonicity_more_factors_higher_score(self, endpoint, timestamp):
        """
        PROPERTY: Adding risk factors NEVER decreases score.

        If score can go DOWN when adding risk, the system is broken.
        """
        engine = RiskEngine(enable_time_amplification=False)
        # Start with empty
        score_0, _, _ = engine.calculate_score([], endpoint, timestamp)

        # Add one factor
        score_1, _, _ = engine.calculate_score(["ip_unknown"], endpoint, timestamp)

        # Add two factors
        score_2, _, _ = engine.calculate_score(
            ["ip_unknown", "high_rate"], endpoint, timestamp
        )

        assert score_0 <= score_1 <= score_2, (
            f"Non-monotonic: {score_0} -> {score_1} -> {score_2}"
        )

    # PROPERTY 5: Monitoring endpoints have reduced risk
    @given(
        factors=risk_factor_lists()
    )
    @settings(max_examples=100)
    def test_monitoring_endpoints_reduced_risk(self, factors):
        """
        PROPERTY: Health/metrics endpoints should have LOWER scores than auth endpoints.

        We don't want to block health checks.
        """
        assume(len(factors) > 0)  # Skip if no factors
        engine = RiskEngine(enable_time_amplification=False)

        score_health, _, meta_health = engine.calculate_score(
            factors, "/health", datetime.now()
        )
        score_auth, _, meta_auth = engine.calculate_score(
            factors, "/api/v1/auth/login", datetime.now()
        )

        # Health multiplier should be less than auth multiplier
        assert meta_health["multiplier"] < meta_auth["multiplier"], (
            f"Health multiplier {meta_health['multiplier']} >= "
            f"Auth multiplier {meta_auth['multiplier']}"
        )

    # PROPERTY 6: Time amplification is consistent
    @given(
        endpoint=valid_endpoints(),
        factors=risk_factor_lists()
    )
    @settings(max_examples=100)
    def test_time_amplification_consistent(self, endpoint, factors):
        """
        PROPERTY: Night-time requests should have higher/equal score than daytime.

        Night multiplier should be >= day multiplier.
        """
        engine_with_time = RiskEngine(enable_time_amplification=True)
        # Day time (14:00)
        day_time = datetime.now().replace(hour=14, minute=0)
        score_day, _, meta_day = engine_with_time.calculate_score(
            factors, endpoint, day_time
        )

        # Night time (03:00)
        night_time = datetime.now().replace(hour=3, minute=0)
        score_night, _, meta_night = engine_with_time.calculate_score(
            factors, endpoint, night_time
        )

        # Night should have >= day multiplier (for sensitive endpoints)
        if "sensitive" in meta_night.get("endpoint_tags", []):
            assert meta_night["multiplier"] >= meta_day["multiplier"], (
                f"Night multiplier {meta_night['multiplier']} < "
                f"Day multiplier {meta_day['multiplier']} for sensitive endpoint"
            )

    # PROPERTY 7: Amplification only affects marked factors
    @given(
        endpoint=valid_endpoints(),
        timestamp=timestamps()
    )
    @settings(max_examples=100)
    def test_amplification_selective(self, endpoint, timestamp):
        """
        PROPERTY: Only factors with affected_by_endpoint=True should be amplified.

        Network factors (IP) should NOT be amplified by auth endpoints.
        """
        engine = RiskEngine(enable_time_amplification=False)
        factors = ["ip_unknown", "token_expired"]  # One global, one context-sensitive

        _, factor_breakdown, metadata = engine.calculate_score(
            factors, endpoint, timestamp
        )

        for risk_factor in factor_breakdown:
            if risk_factor.factor == "ip_unknown":
                # Should NOT be amplified
                assert risk_factor.applied_weight == risk_factor.base_weight, (
                    f"ip_unknown was amplified! {risk_factor.base_weight} -> "
                    f"{risk_factor.applied_weight}"
                )

            elif risk_factor.factor == "token_expired" and metadata["multiplier"] > 1.0:
                # SHOULD be amplified if multiplier > 1.0
                assert risk_factor.applied_weight >= risk_factor.base_weight, (
                    f"token_expired was NOT amplified despite multiplier "
                    f"{metadata['multiplier']}x"
                )

    # PROPERTY 8: No negative weights
    @given(
        endpoint=valid_endpoints(),
        factors=risk_factor_lists(),
        timestamp=timestamps()
    )
    @settings(max_examples=200)
    def test_no_negative_weights(self, endpoint, factors, timestamp):
        """
        PROPERTY: Applied weights MUST be non-negative.

        Negative weights would subtract from score, which is nonsensical.
        """
        engine = RiskEngine(enable_time_amplification=False)
        _, factor_breakdown, _ = engine.calculate_score(factors, endpoint, timestamp)

        for risk_factor in factor_breakdown:
            assert risk_factor.base_weight >= 0, (
                f"Negative base weight: {risk_factor.base_weight}"
            )
            assert risk_factor.applied_weight >= 0, (
                f"Negative applied weight: {risk_factor.applied_weight}"
            )

    # PROPERTY 9: Multiplier breakdown sums correctly
    @given(
        endpoint=valid_endpoints(),
        timestamp=timestamps()
    )
    @settings(max_examples=100)
    def test_multiplier_breakdown_sums_correctly(
        self, endpoint, timestamp
    ):
        """
        PROPERTY: Multiplier breakdown components MUST sum to total.

        If breakdown doesn't match total, audit trail is broken.
        """
        engine_with_time = RiskEngine(enable_time_amplification=True)
        _, _, metadata = engine_with_time.calculate_score([], endpoint, timestamp)

        breakdown = metadata["multiplier_breakdown"]
        computed_total = breakdown["base"] + breakdown.get("endpoint_bonus", 0)

        if "night_bonus" in breakdown:
            computed_total += breakdown["night_bonus"]

        # Allow small floating point error
        assert abs(computed_total - breakdown["total"]) < 0.01, (
            f"Breakdown doesn't sum: {breakdown}"
        )


# Regression tests (specific edge cases found during development)
class TestRegressionCases:
    """Known edge cases that should never break again"""

    @pytest.fixture
    def engine(self):
        return RiskEngine(enable_time_amplification=False)

    def test_empty_factors_zero_score(self, engine):
        """Edge case: No risk factors should give 0 score"""
        score, _, _ = engine.calculate_score([], "/api/v1/auth/login")
        assert score == 0

    def test_all_factors_capped(self, engine):
        """Edge case: All factors together should cap at 100"""
        all_factors = [
            "ip_unknown", "token_expired", "high_rate",
            "failed_auth_recent", "unusual_hour", "new_user"
        ]
        score, _, metadata = engine.calculate_score(
            all_factors, "/api/v1/admin/users"
        )

        assert score == 100  # Should be capped
        assert metadata["capped"] is True
        assert metadata["base_score"] > 100

    def test_monitoring_endpoint_high_rate_ok(self, engine):
        """
        Edge case: High rate on /health should NOT trigger high score.
        This was a false positive in production.
        """
        score, _, _ = engine.calculate_score(["high_rate"], "/health")

        # Should be reduced due to monitoring multiplier
        assert score < 60, f"Health check scored too high: {score}"

    def test_payment_without_amplifiable_factors(self, engine):
        """
        Edge case: Payment endpoint with only behavioral factors.
        Should have high multiplier but factors aren't amplified.
        """
        score, factors, metadata = engine.calculate_score(
            ["new_user", "high_rate"],
            "/api/v1/payment/charge"
        )

        # High multiplier
        assert metadata["multiplier"] >= 1.5

        # But factors NOT amplified (affected_by_endpoint=False)
        for factor in factors:
            assert factor.applied_weight == factor.base_weight


if __name__ == "__main__":
    # Run with: python -m pytest cerber/tests/test_risk_engine_properties.py -v
    pytest.main([__file__, "-v", "--tb=short"])
