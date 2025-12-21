"""
CERBER Post-Crisis Abuse Lock - Tests
RULE-065 verification

Author: Cerber Team
Date: 2025-12-20
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from post_crisis_guard import PostCrisisGuard
from datetime import datetime, timedelta


class TestPostCrisisLock:
    """Tests for RULE-065 (Post-Crisis Abuse Lock)"""

    def setup_method(self):
        """Setup for each test"""
        self.guard = PostCrisisGuard(flag_storage_path="test_crisis_flags.json")

    def teardown_method(self):
        """Cleanup after each test"""
        import os
        try:
            os.remove("test_crisis_flags.json")
        except:
            pass

    # ===== Core Functionality =====

    def test_no_flag_allows_continue(self):
        """Test that no flag allows normal processing"""
        identity = {"user_id": "user_123"}
        result = self.guard.check_post_crisis(identity)
        assert result is None, "Should allow when no crisis flag"

    def test_crisis_flag_blocks_second_attempt(self):
        """Test that crisis flag triggers hard block on repeat"""
        identity = {"user_id": "user_123", "session_id": "session_abc"}

        # Set crisis flag
        self.guard.set_crisis_flag(identity, "suicide")

        # Attempt interaction again
        result = self.guard.check_post_crisis(identity)

        assert result is not None, "Should block on second attempt"
        assert result["action"] == "POST_CRISIS_HARD_BLOCK"
        assert result["terminate"] is True

    def test_different_identity_not_blocked(self):
        """Test that different identity is not affected"""
        identity1 = {"user_id": "user_123"}
        identity2 = {"user_id": "user_456"}

        # Flag identity1
        self.guard.set_crisis_flag(identity1, "fire")

        # Check identity2 (should pass)
        result = self.guard.check_post_crisis(identity2)
        assert result is None, "Different identity should not be blocked"

    def test_flag_persists_across_sessions(self):
        """Test that crisis flag persists (stored to disk)"""
        identity = {"user_id": "user_123"}

        # Set flag
        self.guard.set_crisis_flag(identity, "dying")

        # Create new guard instance (simulates restart)
        guard2 = PostCrisisGuard(flag_storage_path="test_crisis_flags.json")

        # Check flag still exists
        result = guard2.check_post_crisis(identity)
        assert result is not None, "Flag should persist across restarts"

    # ===== Identity Hashing =====

    def test_identity_hash_consistency(self):
        """Test that same identity produces same hash"""
        identity = {"user_id": "user_123", "ip_address": "1.2.3.4"}

        hash1 = self.guard.compute_identity_hash(identity)
        hash2 = self.guard.compute_identity_hash(identity)

        assert hash1 == hash2, "Same identity should produce same hash"

    def test_identity_hash_sensitivity(self):
        """Test that different identities produce different hashes"""
        identity1 = {"user_id": "user_123"}
        identity2 = {"user_id": "user_456"}

        hash1 = self.guard.compute_identity_hash(identity1)
        hash2 = self.guard.compute_identity_hash(identity2)

        assert hash1 != hash2, "Different identities should produce different hashes"

    # ===== TTL and Expiration =====

    def test_expired_flag_removed(self):
        """Test that expired flags are cleaned up"""
        identity = {"user_id": "user_123"}

        # Set flag
        identity_hash = self.guard.set_crisis_flag(identity, "attack")

        # Manually expire flag
        flag = self.guard.flags[identity_hash]
        flag.expires_at = (datetime.now() - timedelta(days=1)).isoformat()

        # Check (should clean up)
        result = self.guard.check_post_crisis(identity)
        assert result is None, "Expired flag should be removed"
        assert identity_hash not in self.guard.flags

    # ===== Hard Block Tracking =====

    def test_hard_blocked_flag_set(self):
        """Test that hard_blocked flag is set after block"""
        identity = {"user_id": "user_123"}

        # Set flag
        identity_hash = self.guard.set_crisis_flag(identity, "weapon")

        # Check (triggers block)
        self.guard.check_post_crisis(identity)

        # Verify flag marked as hard_blocked
        assert self.guard.flags[identity_hash].hard_blocked is True

    # ===== Statistics =====

    def test_statistics_tracking(self):
        """Test statistics are accurate"""
        identity1 = {"user_id": "user_1"}
        identity2 = {"user_id": "user_2"}
        identity3 = {"user_id": "user_3"}

        # Set 3 flags
        self.guard.set_crisis_flag(identity1, "crisis1")
        self.guard.set_crisis_flag(identity2, "crisis2")
        self.guard.set_crisis_flag(identity3, "crisis3")

        # Block 2 of them
        self.guard.check_post_crisis(identity1)
        self.guard.check_post_crisis(identity2)

        stats = self.guard.get_statistics()
        assert stats["total_crisis_flags"] == 3
        assert stats["hard_blocked_identities"] == 2
        assert stats["active_flags"] == 1

    # ===== Edge Cases =====

    def test_empty_identity(self):
        """Test handling of empty identity"""
        identity = {}
        hash1 = self.guard.compute_identity_hash(identity)
        hash2 = self.guard.compute_identity_hash(identity)

        # Should still produce consistent hash
        assert hash1 == hash2

    def test_partial_identity(self):
        """Test handling of partial identity data"""
        identity1 = {"user_id": "user_123"}
        identity2 = {"user_id": "user_123", "session_id": "session_abc"}

        hash1 = self.guard.compute_identity_hash(identity1)
        hash2 = self.guard.compute_identity_hash(identity2)

        # Different identity data = different hash
        assert hash1 != hash2

    # ===== Integration =====

    def test_response_is_minimal(self):
        """Test that hard block response is minimal (no info leak)"""
        identity = {"user_id": "user_123"}

        self.guard.set_crisis_flag(identity, "suicide attempt")
        result = self.guard.check_post_crisis(identity)

        # Response should NOT reveal original crisis details
        assert "Dostęp został zablokowany" in result["response"]
        assert "suicide" not in result["response"]  # No leak


# ===== Run Tests =====

if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "--tb=short"])
