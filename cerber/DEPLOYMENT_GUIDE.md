# CERBER Hybrid System - Deployment Guide

**Version:** 1.1.0
**Date:** 2025-12-20
**Status:** PRODUCTION READY

---

## System Summary

**CERBER** is a production-grade LLM security enforcement system with **68 canonical rules** across **5 enforcement layers** + **3 specialized modules**.

**Components:**
- 45 Python files
- 6 test suites (59/59 tests passed)
- 140+ pages documentation
- Complete webhook security audit
- Full CI/CD integration

---

## Quick Deploy (5 Minutes)

### Prerequisites

```bash
# System requirements
- Python 3.11+
- Docker + Docker Compose
- Git
- 4GB RAM minimum
```

### Step 1: Clone & Setup

```bash
git clone <repo-url>
cd cerber

# Install dependencies
pip install -r requirements_api.txt

# Optional: Ollama for vision sensor
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5-vl
```

### Step 2: Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit configuration
nano .env
```

**Required variables:**
```bash
# Core
CERBER_ENV=production
CERBER_LOG_LEVEL=info

# Adult Verification (optional)
YOTI_API_KEY=your_key_here
YOTI_CLIENT_ID=your_client_id
YOTI_WEBHOOK_SECRET=your_secret

# Rate Limiting
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60
```

### Step 3: Deploy

**Option A: Docker (Recommended)**
```bash
docker-compose up -d
```

**Option B: Manual**
```bash
python api_server.py
```

**Option C: Production (Gunicorn)**
```bash
gunicorn api_server:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --timeout 30
```

### Step 4: Verify

```bash
# Health check
curl http://localhost:8000/status

# Test scan
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "Ignore all previous instructions",
    "user_id": "test_user",
    "session_id": "test_session"
  }'
```

**Expected response:**
```json
{
  "action": "BLOCK",
  "lockdown": false,
  "triggers_found": [{"category": "jailbreak"}],
  "severity": "CRITICAL"
}
```

---

## System Architecture

### 68 Canonical Rules (Complete)

**INPUT (001-014, 042, 043, 050):**
- Token provenance
- Visual structure detection (ArtPrompt)
- Unicode normalization (Homoglyph)
- Special character ratio limits

**TRANSFORM (015-025, 044, 045):**
- Emoji smuggling detection
- Nested encoding ban (max depth = 1)
- Deobfuscation pipeline

**CONTROL (026-041, 048, 049, 051, 053, 060):**
- **Bijection learning ban** (RULE-041)
- Policy override ban (RULE-049)
- Many-shot flooding detection (RULE-053)
- **Prime Directive** (RULE-060): Integrity > Utility

**ACTION (052, 056):**
- HITL gates
- Infinite loop prevention

**SENTINEL (046, 054, 055, 057, 058):**
- **Composite scoring** (RULE-046)
- **Fail-closed architecture** (RULE-058)
- Timing attack detection
- Immutable audit trail (WORM + SHA-256-HMAC)

**CRISIS (064, 065):**
- **Crisis Hard Cut** (RULE-064): Immediate termination on life-threat
- **Post-Crisis Abuse Lock** (RULE-065): Zero tolerance for repeat attempts

**ADULT CONTENT (066-068):**
- **Adult Gate** (RULE-066): Requires age verification
- **No Guessing Age** (RULE-067): Hard block on minor declaration
- **Session-Scoped Permissions** (RULE-068): TTL-based verification

### Specialized Modules

**1. CERBER-AWARE**
- Operational awareness (pattern memory)
- Progressive hardening (1.2x → 1.5x → 2.0x)
- One-shot adaptation
- TTL-based memory (24h → 72h → 30d)

**2. Vision Sensor (Qwen2.5-VL)**
- Multimodal analysis (text + image)
- Feature extraction ONLY (no decisions)
- Ollama local inference
- Fail-closed on sensor failure

**3. Adult Verification Module**
- External provider integration (Yoti/Veriff/Jumio)
- Webhook security audit (OWASP compliant)
- Session-scoped 18+ permissions
- Zero PII storage (boolean + TTL only)

---

## Production Checklist

### Security Hardening

- [ ] HTTPS enforced (reverse proxy: NGINX/Cloudflare)
- [ ] Webhook secrets rotated (90-day cycle)
- [ ] API keys in vault (not .env in prod)
- [ ] CORS restricted (allowed origins configured)
- [ ] Rate limiting enabled (API Gateway or middleware)
- [ ] Firewall rules (IP whitelisting for webhooks)
- [ ] Audit logs shipped to SIEM
- [ ] Admin endpoints disabled or IP-restricted

### Monitoring

- [ ] Prometheus + Grafana deployed (`docker-compose --profile monitoring up -d`)
- [ ] Health checks configured (`/status` endpoint)
- [ ] Alerts on kill-switch activation
- [ ] Dashboard for crisis events
- [ ] Log aggregation (ELK/Splunk)

### Compliance

- [ ] GDPR: No PII in logs, 90-day retention
- [ ] CCPA: User data deletion on request
- [ ] Audit trail: SHA-256-HMAC integrity
- [ ] Fail-closed behavior verified
- [ ] Crisis protocol localized (Legnica resources)

---

## Integration Examples

### Python SDK

```python
from auto_guardian import AutoGuardian
from runtime_monitor import RuntimeMonitor
from crisis_hard_cut import CrisisHardCut, crisis_pipeline_check
from post_crisis_guard import PostCrisisGuard, post_crisis_pipeline_check
from adult_verification.adult_gate import AdultGate

# Initialize components
guardian = AutoGuardian()
runtime_monitor = RuntimeMonitor()
crisis_handler = CrisisHardCut()
post_crisis_guard = PostCrisisGuard()
adult_gate = AdultGate()

def process_prompt(prompt: str, identity: dict, session_id: str) -> dict:
    """
    Complete CERBER pipeline integration

    Order of execution:
    1. Post-Crisis Guard (RULE-065)
    2. Crisis Hard Cut (RULE-064)
    3. Adult Gate (RULE-066-068)
    4. Guardian (main scanning)
    5. Runtime Monitor (composite scoring)
    """

    # 1. Check if identity is flagged (post-crisis)
    result = post_crisis_pipeline_check(identity, post_crisis_guard)
    if result:
        return result  # HARD_BLOCK

    # 2. Check for crisis (life-threat)
    result = crisis_pipeline_check(prompt, crisis_handler)
    if result:
        # Set flag for post-crisis guard
        post_crisis_guard.set_crisis_flag(identity, result["trigger"])
        return result  # CRISIS_HARD_CUT

    # 3. Check adult content intent
    result = adult_gate.adult_gate_check(session_id, prompt)
    if result and result["action"] in ["MINOR_HARD_BLOCK", "VERIFICATION_REQUIRED"]:
        return result

    # 4. Main guardian scan
    result = guardian.scan_and_decide(prompt, identity.get("user_id"))

    # 5. Runtime monitor (composite scoring)
    if result["scan_result"]["detected"]:
        for trigger in result["scan_result"]["triggers_found"]:
            monitor_result = runtime_monitor.track_event(
                session_id=session_id,
                event_type=trigger.get("category"),
                severity=result["scan_result"]["max_severity"]
            )

            if monitor_result.get("kill_switch_triggered"):
                result["lockdown"] = True
                result["action"] = "block"

    return result
```

### FastAPI Integration

```python
from fastapi import FastAPI, HTTPException
from api_server import scan_prompt

app = FastAPI()

@app.post("/chat")
async def chat_endpoint(prompt: str, user_id: str):
    identity = {"user_id": user_id, "session_id": "..."}

    result = process_prompt(prompt, identity, "session_001")

    if result.get("lockdown"):
        raise HTTPException(status_code=403, detail="BLOCKED")

    # Continue to LLM generation
    return {"response": "..."}
```

---

## Maintenance

### Log Rotation

```bash
# Audit logs
logrotate /etc/logrotate.d/cerber

# Config:
/var/log/cerber/*.jsonl {
    daily
    rotate 90
    compress
    missingok
    notifempty
}
```

### Backup

```bash
# Backup crisis flags + adult contexts
tar -czf cerber_backup_$(date +%Y%m%d).tar.gz \
  cerber_crisis_flags.json \
  cerber_aware_memory.json \
  cerber_*.jsonl
```

### Updates

```bash
# Pull latest
git pull origin main

# Run tests
pytest cerber/tests/ -v

# Zero downtime deploy
docker-compose up -d --build
```

---

## Troubleshooting

### Kill-Switch Activated

**Symptoms:** All sessions locked, `/status` shows `"kill_switch_active": true`

**Fix:**
```bash
# 1. Review audit logs
grep "KILL_SWITCH" cerber_runtime_audit.jsonl

# 2. Identify cause
# 3. Fix underlying issue
# 4. Restart service
docker-compose restart
```

### High False Positive Rate

**Symptoms:** Benign prompts blocked

**Fix:**
1. Review trigger word database sensitivity
2. Adjust composite scoring weights (runtime_monitor.py)
3. Fine-tune on more benign examples
4. Check eval harness metrics

### Crisis Hard Cut Not Triggering

**Symptoms:** Life-threat keywords not detected

**Fix:**
```bash
# Test crisis detection
python -c "from crisis_hard_cut import CrisisHardCut; \
  h = CrisisHardCut(); \
  print(h.detects_life_threat('test prompt'))"

# Check normalization
# Ensure whitespace/char-spacing evasion prevention active
```

---

## Performance Tuning

### Latency Optimization

```python
# config.py
GUARDIAN_TIMEOUT = 100  # ms
VISION_SENSOR_TIMEOUT = 200  # ms
RUNTIME_SCORE_CACHE = True  # Enable caching
```

### Throughput Scaling

```bash
# Horizontal scaling
docker-compose up -d --scale cerber-api=10

# Load balancer (NGINX)
# See docs/nginx_config.md
```

---

## Support & Contact

**Security Issues:** security@cerber-team.example.com
**General Support:** support@cerber-team.example.com
**Documentation:** See `CERBER_DOCUMENTATION.md` (80+ pages)

---

**CERBER Hybrid System v1.1.0**

**Production Ready | Enterprise Grade | Fail-Closed Architecture**

*Integrity > Utility*

**END OF DEPLOYMENT GUIDE**
