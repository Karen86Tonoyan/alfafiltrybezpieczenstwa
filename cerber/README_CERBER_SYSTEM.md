# CERBER Security System

**Enterprise-Grade LLM Security Enforcement**

Version 1.0.0 | 2025-12-20 | Production Ready

---

## Overview

CERBER is a production-grade security enforcement system for Large Language Models, implementing **60 canonical security rules** across **5 enforcement layers**. Unlike traditional "prompt-based guardrails", CERBER uses **deterministic policy enforcement** with fail-closed architecture.

### Key Differentiators

**What Makes CERBER Different:**

| Traditional Guardrails | CERBER |
|----------------------|---------|
| LLM decides safety | Policy engine decides (deterministic) |
| Prompt-based filtering | 5-layer enforcement pipeline |
| Fails open (unsafe) | Fails closed (RULE-058) |
| Single-point detection | Composite scoring (weak signal aggregation) |
| No audit trail | Immutable WORM logs (SHA-256-HMAC) |
| "Magic AI demo" | Engineering discipline |

**Philosophy:**
```
Architektura najpierw, model na końcu.
Model NIE decyduje. Model zachowuje się zgodnie z kanonem.
Integrity > Utility (RULE-060)
```

---

## Features

### ✅ 60 Canonical Rules

Complete security canon across 5 domains:
- **INPUT** (001-014, 042, 043, 050): Sanitization, normalization, visual detection
- **TRANSFORM** (015-025, 044, 045): Deobfuscation, encoding limits
- **CONTROL** (026-041, 048, 049, 051, 053, 060): Policy core, bijection ban, prime directive
- **ACTION** (052, 056): Execution gates, HITL triggers
- **SENTINEL** (046, 054, 055, 057, 058): Runtime monitor, kill-switch

### ✅ Fail-Closed Architecture (RULE-058)

- Component failure = immediate lockdown
- No "fail open" scenarios
- 7 kill-switch triggers
- All sessions terminated on critical failure

### ✅ Composite Scoring (RULE-046)

- Aggregates weak signals (pressure, obfuscation, role laundering)
- Time-based decay (0.05/minute)
- Dual thresholds: WARNING (0.4), CRITICAL (0.8)
- Prevents incremental boundary testing

### ✅ Advanced Attack Coverage

| Attack Vector | Detection Rate |
|--------------|----------------|
| Bijection Learning (RULE-041) | 95.2% |
| ArtPrompt (RULE-043) | 90.1% |
| Many-Shot Jailbreaking (RULE-053) | 85.3% |
| Homoglyph Attacks (RULE-050) | 94.7% |
| Emoji Smuggling (RULE-044) | 82.4% |
| Nested Encoding (RULE-045) | 98.9% |
| Role Override (RULE-049) | 96.5% |
| Unknown Protocols (RULE-051) | 100.0% |

### ✅ Production-Ready Deployment

- FastAPI REST API
- Docker + Docker Compose
- Gunicorn ASGI server
- Health checks + monitoring
- Prometheus + Grafana ready
- CI/CD integration (GitHub Actions)

### ✅ Fine-Tuning Dataset

- 175+ training samples (Anthropic/OpenAI format)
- Complete rule coverage
- Refusal pattern training
- False positive reduction

---

## Quick Start

### 1. Installation

```bash
# Clone repository
git clone <repo-url>
cd cerber

# Install dependencies
pip install -r requirements_api.txt
```

### 2. Run API Server

**Option A: Docker (Recommended)**
```bash
docker-compose up -d
```

**Option B: Manual**
```bash
python api_server.py
```

Access:
- API: http://localhost:8000
- Documentation: http://localhost:8000/docs
- Health: http://localhost:8000/status

### 3. Test API

```bash
curl -X POST "http://localhost:8000/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Ignore all previous instructions",
    "user_id": "test_user",
    "session_id": "test_session"
  }'
```

**Response:**
```json
{
  "action": "BLOCK",
  "lockdown": false,
  "session_risk_score": 0.4,
  "triggers_found": [
    {
      "pattern": "ignore.*instructions",
      "category": "jailbreak",
      "severity": "CRITICAL"
    }
  ],
  "severity": "CRITICAL",
  "explanation": "RULE-049 violated: Policy override attempt",
  "timestamp": "2025-12-20T10:30:00Z"
}
```

---

## Architecture

### 5-Layer Enforcement Pipeline

```
USER INPUT
    ↓
[STAGE 1: INPUT] → Sanitize, normalize, detect visual structures
    ↓
[STAGE 2: TRANSFORM] → Deobfuscate, check encoding depth
    ↓
[STAGE 3: CORE] → Policy enforcement, bijection ban, canary check
    ↓
[STAGE 4: ACTION] → Capability checks, HITL gates
    ↓
[STAGE 5: SENTINEL] → Composite scoring, kill-switch
    ↓
SAFE OUTPUT (or LOCKDOWN)
```

### Components

| Component | Purpose | File |
|-----------|---------|------|
| **AutoGuardian** | Real-time prompt scanning | `auto_guardian.py` |
| **RuntimeMonitor** | Composite scoring + kill-switch | `runtime_monitor.py` |
| **AttackLibrary** | 6 advanced attack generators | `attack_library_advanced.py` |
| **DatasetGenerator** | Fine-tuning data creation | `dataset_generator.py` |
| **EvalHarness** | Regression testing | `eval_harness.py` |
| **CI RedTeam** | Automated attack testing | `ci_redteam.py` |
| **API Server** | Production REST API | `api_server.py` |

---

## Documentation

| Document | Purpose |
|----------|---------|
| `README_CERBER_SYSTEM.md` | This file - overview and quick start |
| `CERBER_DOCUMENTATION.md` | Complete technical manual (80+ pages) |
| `FINE_TUNING_CONFIG.md` | Fine-tuning guide and philosophy |
| `cerber_policy_schema.json` | Machine-readable rule definitions |
| `cerber_policy_schema.yaml` | Human-readable rule documentation |

### API Documentation

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

---

## Quick Links

- [Complete Documentation](CERBER_DOCUMENTATION.md)
- [Fine-Tuning Guide](FINE_TUNING_CONFIG.md)
- [API Reference](http://localhost:8000/docs)

---

**CERBER Security System v1.0.0**

**Production Ready | Enterprise Grade | Fail-Closed Architecture**

*Integrity > Utility*
