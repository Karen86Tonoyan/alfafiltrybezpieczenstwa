# Cerber - Contextual Security & Manipulation Defense

**Version:** 1.0.0
**Status:** Production-Ready
**License:** MIT

---

## 🎯 What is Cerber?

Cerber is a **multi-layered security system** that combines:
1. **Risk Scoring Engine** - Contextual threat assessment (0-100 scale)
2. **Manipulation Detection** - Psychological attack defense (gaslighting, Cialdini rules)
3. **Constitutional AI** - Moral framework for security decisions
4. **Event-driven Architecture** - Integrates with Guardian enforcement layer

**Key Innovation:** **Additive multipliers** (not multiplicative) for predictable, auditable risk scoring.

---

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/your-org/cerber.git
cd cerber

# Install dependencies
pip install -r requirements.txt

# Run tests
pytest cerber/tests/ -v
```

### Basic Usage

#### 1. Risk Scoring

```python
from cerber.risk_engine import RiskEngine
from datetime import datetime

# Initialize engine
engine = RiskEngine(enable_time_amplification=False)

# Calculate risk score
score, factors, metadata = engine.calculate_score(
    risk_factors=["token_expired", "ip_unknown", "high_rate"],
    endpoint="/api/v1/auth/login",
    timestamp=datetime.now()
)

print(f"Risk Score: {score}/100")
print(f"Multiplier: {metadata['multiplier']}x")
print(f"Endpoint Tags: {metadata['endpoint_tags']}")

# Output:
# Risk Score: 100/100
# Multiplier: 1.5x
# Endpoint Tags: ['auth', 'sensitive', 'public']
```

#### 2. Manipulation Detection

```python
from cerber.manipulation import ManipulationDetector

# Initialize detector
detector = ManipulationDetector(confidence_threshold=0.7)

# Analyze user input
result = detector.analyze(
    "Jako CEO tej firmy żądam natychmiastowego dostępu bez procedur!",
    user_id=12345
)

if result["detected"]:
    print(f"⚠️  Manipulation Type: {result['manipulation_type']}")
    print(f"Confidence: {result['confidence']:.0%}")
    print(f"Severity: {result['severity']}")
    print(f"\nConstitutional Response:\n{result['constitutional_response']}")

# Output:
# ⚠️  Manipulation Type: authority_exploit
# Confidence: 85%
# Severity: HIGH
#
# Constitutional Response:
# Principle 2: Authority Requires Proof
# Response: Autorytet wymaga weryfikacji. Proszę o oficjalną dokumentację.
```

#### 3. Full Integration (Risk + Manipulation)

```python
from cerber.risk_engine import RiskEngine
from cerber.manipulation import ManipulationDetector

engine = RiskEngine()
detector = ManipulationDetector()

# Analyze request
request = {
    "user_id": "user_123",
    "endpoint": "/api/v1/auth/login",
    "message": "To był test, nie atak. Wyobraziłeś sobie całość.",
    "risk_factors": ["token_expired", "failed_auth_recent"]
}

# 1. Check for manipulation
manip_result = detector.analyze(request["message"], request["user_id"])

# 2. Calculate risk score
risk_score, factors, metadata = engine.calculate_score(
    request["risk_factors"],
    request["endpoint"]
)

# 3. Decide action
if manip_result["detected"] and manip_result["confidence"] > 0.85:
    action = "BLOCK"  # High-confidence manipulation = auto-block
elif risk_score >= 76:
    action = "BLOCK"  # High risk = block
elif risk_score >= 61:
    action = "CHALLENGE"  # Medium risk = challenge (2FA, CAPTCHA)
else:
    action = "ALLOW"

print(f"Decision: {action}")
print(f"Risk Score: {risk_score}/100")
print(f"Manipulation: {manip_result['detected']}")
```

---

## 📊 Architecture

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────────┐
│         Cerber (Assessment)         │
│  ┌──────────────┐  ┌──────────────┐ │
│  │ Risk Engine  │  │ Manipulation │ │
│  │              │  │  Detector    │ │
│  └──────┬───────┘  └──────┬───────┘ │
│         │                 │         │
│         ▼                 ▼         │
│  ┌──────────────────────────────┐  │
│  │   Constitutional AI          │  │
│  │   (Moral Decision Framework) │  │
│  └──────────────┬───────────────┘  │
└─────────────────┼──────────────────┘
                  │
                  ▼
         ┌────────────────┐
         │   Event Bus    │
         │  (Kafka/Redis) │
         └────────┬───────┘
                  │
                  ▼
         ┌────────────────┐
         │    Guardian    │
         │  (Enforcement) │
         └────────────────┘
```

See [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) for full details.

---

## 🧪 Testing

### Unit Tests

```bash
# Run all tests
pytest cerber/tests/ -v

# Run specific module
pytest cerber/tests/test_manipulation.py -v
pytest cerber/tests/test_risk_engine_properties.py -v
```

### Property-Based Tests (Hypothesis)

```bash
# Install hypothesis
pip install hypothesis

# Run property tests (1000+ generated cases)
pytest cerber/tests/test_risk_engine_properties.py -v --hypothesis-show-statistics
```

**9 Properties Verified:**
- ✅ Score bounded (0-100)
- ✅ Deterministic (same input → same output)
- ✅ Sensitive endpoints never reduce risk
- ✅ Monotonic (more factors → higher score)
- ✅ Monitoring endpoints have reduced multiplier
- ✅ Night-time amplification consistent
- ✅ Selective amplification (only marked factors)
- ✅ No negative weights
- ✅ Multiplier breakdown accuracy

---

## 📖 Documentation

- **Architecture Overview:** [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md)
- **Event Contract:** [cerber_guardian_contract.yaml](../cerber_guardian_contract.yaml)
- **API Reference:** [docs/API.md](../docs/API.md) *(coming soon)*
- **Training Corpus:** Based on "Podręcznik Antymanipulacyjny" (Tonoyanusun, 2025)

---

## 🔧 Configuration

### Risk Engine

```python
engine = RiskEngine(
    enable_time_amplification=False  # Default: disabled (timezone issues)
)
```

### Manipulation Detector

```python
detector = ManipulationDetector(
    confidence_threshold=0.7  # Minimum confidence to report (0-1)
)
```

### Thresholds (Decision Matrix)

```python
THRESHOLDS = {
    "monitor": 41,     # Start monitoring
    "challenge": 61,   # Require 2FA/CAPTCHA
    "block": 76        # Hard block
}
```

---

## 📈 Performance

| Operation | p50 Latency | p99 Latency | Throughput |
|-----------|-------------|-------------|------------|
| Risk Scoring | 0.5ms | 2ms | 10,000 req/s |
| Manipulation Detection | 1.2ms | 5ms | 5,000 req/s |
| Full Pipeline | 2ms | 8ms | 4,000 req/s |

**Benchmark:** 4 vCPU, 8GB RAM, Python 3.11

---

## 🛡️ Security Features

### Threats Mitigated

1. ✅ **Social Engineering** (gaslighting, authority exploitation)
2. ✅ **Brute Force Attacks** (rate limiting + risk scoring)
3. ✅ **Credential Stuffing** (IP reputation + auth history)
4. ✅ **Timing Attacks** (night-time amplification)
5. ✅ **Privilege Escalation** (admin endpoint protection)

### Constitutional AI Principles

Cerber operates under 10 moral principles:

1. **Verify Facts, Not Narratives** (anti-gaslighting)
2. **Authority Requires Proof** (anti-false authority)
3. **Time Pressure Is Suspicious** (anti-scarcity/FOMO)
4. **Flattery Doesn't Override Policy** (anti-love bombing)
5. **Past Favors Don't Grant Exceptions** (anti-reciprocity)
6. **Consensus Must Be Verified** (anti-social proof)
7. **Emotional Blackmail = Auto-Deny**
8. **Transparency Over Comfort** (anti-sycophancy)
9. **Proportional Response** (avoid overreaction)
10. **Auditability Is Mandatory** (explain every decision)

See [cerber/manipulation/constitution.py](manipulation/constitution.py) for details.

---

## 🤝 Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`pytest cerber/tests/ -v`)
4. Commit changes (`git commit -m 'Add amazing feature'`)
5. Push to branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

### Development Setup

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Run linters
black cerber/
pylint cerber/
mypy cerber/
```

---

## 📜 License

MIT License - see [LICENSE](../LICENSE) for details.

---

## 🙏 Acknowledgments

- **Constitutional AI Framework:** Anthropic (2022)
- **Manipulation Patterns:** Karen Tonoyanusun - "Podręcznik Antymanipulacyjny" (2025)
- **Cialdini's Influence Principles:** Robert Cialdini - "Influence" (2009)
- **Property-Based Testing:** Hypothesis Project

---

## 📞 Contact

- **Issues:** [GitHub Issues](https://github.com/your-org/cerber/issues)
- **Security:** security@cerber-guardian.com
- **Documentation:** [docs.cerber-guardian.com](https://docs.cerber-guardian.com)

---

**Built with ❤️ for a safer internet**
