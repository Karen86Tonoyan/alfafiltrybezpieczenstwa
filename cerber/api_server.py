"""
CERBER API Server (FastAPI)
Production-ready REST API dla systemu CERBER

Endpoints:
- POST /scan - Skanuj prompt
- POST /analyze - Głęboka analiza z vision
- GET /status - Status systemu
- GET /stats - Statystyki
- POST /train - Generate training data

Author: Cerber Team
Version: 1.0.0
Date: 2025-12-20
"""

import sys
import io

# Fix Windows console encoding
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, List, Optional
from datetime import datetime
import uvicorn

# Import CERBER modules
from auto_guardian import AutoGuardian
from runtime_monitor import RuntimeMonitor
from attack_library_advanced import (
    ArtPromptGenerator,
    BijectionLearningGenerator,
    ManyShotGenerator,
    HomoglyphGenerator,
    EmojiSmugglingGenerator,
    HexBase64Generator
)
from dataset_generator import CerberDatasetGenerator


# ===== API Models =====

class ScanRequest(BaseModel):
    """Request for prompt scanning"""
    prompt: str = Field(..., description="Prompt to scan", min_length=1)
    user_id: str = Field(default="anonymous", description="User identifier")
    session_id: str = Field(default="default", description="Session identifier")
    enable_deep_analysis: bool = Field(default=False, description="Enable vision-based analysis")


class ScanResponse(BaseModel):
    """Response from prompt scanning"""
    action: str = Field(..., description="ALLOW | BLOCK | WARN")
    lockdown: bool = Field(..., description="Kill-switch activated")
    session_risk_score: float = Field(default=0.0, description="Current session risk")
    triggers_found: List[Dict] = Field(default=[], description="Detected trigger patterns")
    severity: str = Field(default="NONE", description="Max severity level")
    explanation: str = Field(..., description="Human-readable explanation")
    timestamp: str = Field(..., description="Scan timestamp")


class StatusResponse(BaseModel):
    """System status"""
    system_status: str = Field(..., description="OPERATIONAL | LOCKDOWN")
    kill_switch_active: bool
    total_sessions: int
    locked_sessions: int
    average_risk_score: float
    uptime_seconds: float
    version: str = "1.0.0"


class TrainingRequest(BaseModel):
    """Request for training data generation"""
    malicious_per_rule: int = Field(default=5, ge=1, le=20)
    benign_count: int = Field(default=100, ge=10, le=500)
    composite_count: int = Field(default=30, ge=5, le=100)
    format_type: str = Field(default="anthropic", pattern="^(anthropic|openai)$")


class AttackGenerationRequest(BaseModel):
    """Request for attack generation (red team testing)"""
    attack_type: str = Field(..., description="artprompt | bijection | manyshot | homoglyph | emoji | encoding")
    payload: str = Field(..., description="Target payload")
    parameters: Optional[Dict] = Field(default={}, description="Attack-specific parameters")


# ===== FastAPI App =====

app = FastAPI(
    title="CERBER Security API",
    description="Production-grade LLM security enforcement system with 60 canonical rules",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware (configure for production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global instances
guardian = AutoGuardian(
    enable_ollama_mixing=False,  # Disable for production
    log_file="cerber_api_audit.jsonl"
)

runtime_monitor = RuntimeMonitor(
    audit_log_path="cerber_runtime_audit.jsonl"
)

# Server start time for uptime tracking
server_start_time = datetime.now()


# ===== Endpoints =====

@app.get("/", tags=["General"])
async def root():
    """API root - health check"""
    return {
        "service": "CERBER Security API",
        "version": "1.0.0",
        "status": "operational" if not runtime_monitor.kill_switch_active else "lockdown",
        "documentation": "/docs"
    }


@app.post("/scan", response_model=ScanResponse, tags=["Security"])
async def scan_prompt(request: ScanRequest):
    """
    Skanuj prompt przez CERBER Guardian

    Returns:
        ScanResponse with action (ALLOW/BLOCK/WARN) and detailed analysis
    """
    try:
        # Guardian scan
        guardian_result = guardian.scan_and_decide(
            prompt=request.prompt,
            user_id=request.user_id
        )

        # Runtime monitor tracking
        if guardian_result["scan_result"]["detected"]:
            # Track each trigger as event
            for trigger in guardian_result["scan_result"]["triggers_found"]:
                event_type = trigger.get("category", "unknown_threat")

                monitor_result = runtime_monitor.track_event(
                    session_id=request.session_id,
                    event_type=event_type,
                    severity=guardian_result["scan_result"]["max_severity"],
                    details={
                        "trigger": trigger,
                        "user_id": request.user_id
                    }
                )

                # Override if monitor escalated
                if monitor_result.get("kill_switch_triggered"):
                    guardian_result["lockdown"] = True
                    guardian_result["action"] = "block"

        # Get session risk score
        session_report = runtime_monitor.get_session_report(request.session_id)
        session_risk = session_report["total_risk_score"] if session_report else 0.0

        # Build response
        response = ScanResponse(
            action=guardian_result["action"].upper(),
            lockdown=guardian_result["lockdown"],
            session_risk_score=session_risk,
            triggers_found=guardian_result["scan_result"].get("triggers_found", []),
            severity=guardian_result["scan_result"].get("max_severity", "NONE"),
            explanation=guardian_result.get("response") or "Prompt analysis complete",
            timestamp=datetime.now().isoformat()
        )

        return response

    except Exception as e:
        # Fail-closed (RULE-058)
        runtime_monitor.trigger_kill_switch("API_EXCEPTION")
        raise HTTPException(
            status_code=500,
            detail=f"CERBER LOCKDOWN: Internal error - {str(e)}"
        )


@app.get("/status", response_model=StatusResponse, tags=["Monitoring"])
async def get_status():
    """
    Pobierz status systemu CERBER
    """
    try:
        system_status = runtime_monitor.get_system_status()
        uptime = (datetime.now() - server_start_time).total_seconds()

        return StatusResponse(
            system_status="LOCKDOWN" if system_status["kill_switch_active"] else "OPERATIONAL",
            kill_switch_active=system_status["kill_switch_active"],
            total_sessions=system_status["total_sessions"],
            locked_sessions=system_status["locked_sessions"],
            average_risk_score=system_status["average_risk_score"],
            uptime_seconds=uptime
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/stats", tags=["Monitoring"])
async def get_statistics():
    """
    Pobierz szczegółowe statystyki
    """
    try:
        guardian_stats = guardian.get_statistics()
        runtime_stats = runtime_monitor.get_system_status()

        return {
            "guardian": guardian_stats,
            "runtime_monitor": runtime_stats,
            "uptime_seconds": (datetime.now() - server_start_time).total_seconds()
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/session/{session_id}", tags=["Monitoring"])
async def get_session_report(session_id: str):
    """
    Pobierz raport dla konkretnej sesji
    """
    report = runtime_monitor.get_session_report(session_id)

    if not report:
        raise HTTPException(
            status_code=404,
            detail=f"Session {session_id} not found"
        )

    return report


@app.post("/train", tags=["Admin"])
async def generate_training_data(
    request: TrainingRequest,
    background_tasks: BackgroundTasks
):
    """
    Generuj dane treningowe (async w tle)

    UWAGA: To endpoint adminowy - zabezpiecz w produkcji!
    """
    def generate_in_background():
        generator = CerberDatasetGenerator()
        generator.generate_full_dataset(
            malicious_per_rule=request.malicious_per_rule,
            benign_count=request.benign_count,
            composite_count=request.composite_count
        )

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"cerber_training_{timestamp}.jsonl"

        generator.export_jsonl(output_file, format_type=request.format_type)
        generator.export_statistics(f"cerber_stats_{timestamp}.json")

    background_tasks.add_task(generate_in_background)

    return {
        "status": "Training data generation started",
        "parameters": request.dict(),
        "note": "Files will be generated in background"
    }


@app.post("/redteam/generate", tags=["Red Team"])
async def generate_attack(request: AttackGenerationRequest):
    """
    Generuj atak dla celów testowych (red team)

    UWAGA: Endpoint do testowania - zabezpiecz w produkcji!
    """
    try:
        attack_generators = {
            "artprompt": ArtPromptGenerator,
            "bijection": BijectionLearningGenerator,
            "manyshot": ManyShotGenerator,
            "homoglyph": HomoglyphGenerator,
            "emoji": EmojiSmugglingGenerator,
            "encoding": HexBase64Generator
        }

        generator = attack_generators.get(request.attack_type)
        if not generator:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown attack type: {request.attack_type}"
            )

        # Generate attack
        if request.attack_type == "artprompt":
            attack = generator.generate_attack(
                request.payload,
                framing=request.parameters.get("framing", "educational")
            )
        elif request.attack_type == "bijection":
            attack = generator.generate_attack(
                request.payload,
                cipher_type=request.parameters.get("cipher_type", "symbol")
            )
        elif request.attack_type == "manyshot":
            attack = generator.generate_attack(
                request.payload,
                shots=request.parameters.get("shots", 50)
            )
        elif request.attack_type == "homoglyph":
            attack = generator.generate_attack(
                request.payload,
                intensity=request.parameters.get("intensity", 0.7)
            )
        elif request.attack_type == "emoji":
            attack = generator.generate_attack(request.payload)
        else:  # encoding
            attack = generator.generate_attack(
                request.payload,
                encoding=request.parameters.get("encoding", "layered")
            )

        return {
            "attack_type": request.attack_type,
            "generated_attack": attack,
            "length": len(attack),
            "warning": "This is for authorized red team testing only"
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/admin/reset-session/{session_id}", tags=["Admin"])
async def reset_session(session_id: str):
    """
    Zresetuj sesję (admin only)

    UWAGA: Zabezpiecz w produkcji!
    """
    if session_id in runtime_monitor.sessions:
        del runtime_monitor.sessions[session_id]
        return {"status": "Session reset", "session_id": session_id}
    else:
        raise HTTPException(status_code=404, detail="Session not found")


@app.post("/admin/kill-switch/activate", tags=["Admin"])
async def activate_kill_switch(reason: str = "MANUAL_ADMIN_TRIGGER"):
    """
    Aktywuj kill-switch ręcznie (EMERGENCY)

    UWAGA: To zatrzyma cały system!
    """
    runtime_monitor.trigger_kill_switch(reason)

    return {
        "status": "KILL-SWITCH ACTIVATED",
        "reason": reason,
        "timestamp": datetime.now().isoformat(),
        "all_sessions_locked": True
    }


# ===== Server Startup =====

def main():
    """Run CERBER API server"""
    print("=" * 80)
    print("[*] CERBER Security API")
    print("[*] Starting production server...")
    print("=" * 80)
    print(f"\n[*] Documentation: http://localhost:8000/docs")
    print(f"[*] Status endpoint: http://localhost:8000/status")
    print(f"[*] Scan endpoint: http://localhost:8000/scan")
    print("\n[!] WARNING: Secure admin endpoints before production deployment!")
    print("=" * 80)

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info",
        access_log=True
    )


if __name__ == "__main__":
    main()
