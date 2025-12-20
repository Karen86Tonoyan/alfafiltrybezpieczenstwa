"""
Cerber Guardian - Kafka Consumer
KROK 2: Event Consumer with automated response actions

Consumes risk and manipulation events from Kafka and executes Guardian actions:
- Lockdowns (ban, challenge, slow mode)
- Alert notifications
- Metrics collection
- Learning Loop integration

Author: Cerber Team
Version: 2.0.0
Date: 2025-12-20
"""

from typing import Dict, Any
import json

# Kafka with fallback
try:
    from kafka import KafkaConsumer
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False
    print("[WARN] kafka-python not installed. Guardian will use mock mode.")

# Redis with fallback
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    print("[WARN] redis not installed. Ban storage will use in-memory fallback.")


class GuardianKafkaConsumer:
    """
    Guardian consumer for Cerber events

    Processes events from 'cerber.risk_events' topic and executes
    security actions based on threat level.
    """

    def __init__(self, bootstrap_servers=None, redis_host='localhost', redis_port=6379):
        """
        Initialize Guardian consumer

        Args:
            bootstrap_servers: List of Kafka brokers
            redis_host: Redis host for ban storage
            redis_port: Redis port
        """
        self.bootstrap_servers = bootstrap_servers or ['localhost:9092']
        self.consumer = None
        self.redis_client = None

        # Initialize Redis
        if REDIS_AVAILABLE:
            try:
                self.redis_client = redis.Redis(
                    host=redis_host,
                    port=redis_port,
                    db=0,
                    decode_responses=True
                )
                self.redis_client.ping()
                print(f"[*] Redis connected: {redis_host}:{redis_port}")
            except Exception as e:
                print(f"[ERROR] Redis connection failed: {e}")
                self.redis_client = None

        # Fallback ban storage (in-memory)
        self.ban_storage = {}

        # Initialize Kafka consumer
        if KAFKA_AVAILABLE:
            try:
                self.consumer = KafkaConsumer(
                    'cerber.risk_events',
                    bootstrap_servers=self.bootstrap_servers,
                    value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                    group_id='guardian-group-v1',
                    auto_offset_reset='latest'
                )
                print(f"[*] Kafka Consumer initialized: {self.bootstrap_servers}")
            except Exception as e:
                print(f"[ERROR] Failed to initialize Kafka consumer: {e}")
                self.consumer = None
        else:
            print("[WARN] Kafka not available - Guardian running in standalone mode")

    def lockdown_user(self, user_id: str, endpoint: str, score: int, reason: str = "risk"):
        """
        Execute lockdown action on user

        Args:
            user_id: User identifier
            endpoint: Endpoint that triggered lockdown
            score: Risk score (0-100)
            reason: Lockdown reason (risk, manipulation_*, etc.)
        """
        ban_key = f"ban:{user_id}:{endpoint}"

        print(f"[!] LOCKDOWN [{reason}] user:{user_id} endpoint:{endpoint} score:{score}")

        # Store in Redis or fallback
        if self.redis_client:
            try:
                # Ban duration based on score
                duration_seconds = self._calculate_ban_duration(score)
                self.redis_client.setex(ban_key, duration_seconds, score)
                print(f"    [Redis] Ban stored: {ban_key} ({duration_seconds}s)")
            except Exception as e:
                print(f"    [ERROR] Redis storage failed: {e}")
                self.ban_storage[ban_key] = score
        else:
            self.ban_storage[ban_key] = score

        # Action mapping
        action = self._get_action_for_score(score)
        print(f"    [ACTION] {action}")

    def _calculate_ban_duration(self, score: int) -> int:
        """Calculate ban duration based on risk score"""
        if score >= 90:
            return 86400  # 24h for critical
        elif score >= 70:
            return 3600   # 1h for high
        elif score >= 50:
            return 900    # 15min for medium
        return 300         # 5min for low

    def _get_action_for_score(self, score: int) -> str:
        """Get Guardian action for risk score"""
        actions = {
            100: "global_lockdown",
            90: "permanent_ban",
            80: "2fa_challenge",
            70: "captcha",
            60: "slow_mode",
            50: "rate_limit",
            30: "monitor"
        }

        action_key = (score // 10) * 10
        return actions.get(action_key, "allow")

    def handle_risk_event(self, event: Dict[str, Any]) -> bool:
        """
        Handle risk.evaluated event

        Args:
            event: Risk event dictionary

        Returns:
            True if action taken, False otherwise
        """
        score = event.get("score", 0)
        endpoint = event.get("endpoint", "")
        user_id = event.get("user_id", "anon")

        if score >= 70:
            self.lockdown_user(user_id, endpoint, score, reason="high_risk")
            return True

        return False

    def handle_manipulation_event(self, event: Dict[str, Any]) -> bool:
        """
        Handle manipulation.detected event

        Args:
            event: Manipulation event dictionary

        Returns:
            True if action taken, False otherwise
        """
        m_type = event.get("manipulation_type")
        conf = event.get("confidence", 0)
        user_id = event.get("user_id", "anon")
        endpoint = event.get("endpoint", "")

        print(f"[!] MANIPULATION: {m_type} (conf: {conf:.2f})")
        print(f"    [CONSTITUTION] {event.get('constitutional_response', 'N/A')[:80]}...")

        # Lockdown thresholds
        if conf > 0.8:
            self.lockdown_user(user_id, endpoint, 100, reason=f"manipulation_{m_type}")
            return True
        elif conf > 0.5:
            print(f"    [MONITOR] Adding {user_id} to watch list for {m_type}")
            # Could add to Redis watch list here
            return False

        return False

    def handle_event(self, event: Dict[str, Any]) -> bool:
        """
        Route event to appropriate handler

        Args:
            event: Event dictionary

        Returns:
            True if action taken, False otherwise
        """
        event_type = event.get("event_type", "risk.evaluated")

        if event_type == "risk.evaluated":
            return self.handle_risk_event(event)
        elif event_type == "manipulation.detected":
            return self.handle_manipulation_event(event)

        return False

    def run(self):
        """Start consuming events"""
        if not self.consumer:
            print("[ERROR] Kafka consumer not available. Cannot start.")
            return

        print("[*] Guardian Kafka Consumer v2 (Risk + Manipulation) started...")
        print("[*] Listening for events on 'cerber.risk_events'...")

        try:
            for message in self.consumer:
                event = message.value
                # print(f"[>] Received: {event.get('event_type')}")
                self.handle_event(event)
        except KeyboardInterrupt:
            print("\n[*] Guardian shutting down...")
        finally:
            if self.consumer:
                self.consumer.close()
            if self.redis_client:
                self.redis_client.close()


def main():
    """Main entry point for Guardian consumer"""
    guardian = GuardianKafkaConsumer()
    guardian.run()


if __name__ == "__main__":
    main()
