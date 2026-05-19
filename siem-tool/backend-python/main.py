"""
SIEM Backend API - Python/FastAPI
Main entry point for the log parsing and analysis API
"""

import os
import sys
import re
import json
import uuid
import threading
from datetime import datetime
from typing import Optional, List, Dict, Any

# Load environment variables from .env file
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

from pydantic import BaseModel
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Body, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

try:
    from parsers import auto_parse, detect_log_type, generate_stats as gen_stats
    from detectors.alerts import run_detections
    from detectors.correlation import correlate_events
    from ml.classifier import detect_ml_attacks, enrich_entries_with_attacks
    from siem_report_generator import SIEMPDFReport
    from forensic_tasks import task_manager, TaskStatus, FORENSIC_PIPELINE_AVAILABLE

    PARSERS_AVAILABLE = True
except ImportError as e:
    print(f"Import error: {e}")
    PARSERS_AVAILABLE = False

from ai_client import get_soc_client, SOC_MODEL


# SOC Analyst LLM Integration - Using OpenRouter Cloud AI
_soc_model = SOC_MODEL


def _get_soc_client():
    """Proxy for backward compatibility in main.py"""
    return get_soc_client()


# Request/Response Models
class ReportRequest(BaseModel):
    data: Dict[str, Any]
    soc_summary: Optional[str] = None


class LogAnalysisRequest(BaseModel):
    log_entry: str
    log_type: Optional[str] = "unknown"


class ChatRequest(BaseModel):
    message: str
    context: Optional[List[Dict]] = []
    analysis_context: Optional[Dict[str, Any]] = None


class LogAnalysisResponse(BaseModel):
    analysis: str
    attack_detected: bool
    severity: str


class ChatResponse(BaseModel):
    response: str


class ForensicStartRequest(BaseModel):
    image_path: str


class LogChunk(BaseModel):
    name: str
    content: str


class CorrelationRequest(BaseModel):
    logs: List[LogChunk]


class ChunkedParseRequest(BaseModel):
    chunks: List[str]
    fileName: Optional[str] = None
    forceType: Optional[str] = None


# Attack patterns for keyword-based detection
ATTACK_PATTERNS = {
    "bruteforce": {
        "patterns": [
            r"Failed password",
            r"authentication failure",
            r"authentication failed",
            r"Invalid user",
            r"too many failed attempts",
            r"SASL.*failed",
        ],
        "weight": 0.85,
    },
    "sql_injection": {
        "patterns": [
            r"' OR '1'='1", 
            r"UNION\s+SELECT", 
            r"DROP\s+TABLE", 
            r"INSERT\s+INTO",
            r"UPDATE\s+.*\s+SET",
            r"SELECT\s+.*\s+FROM\s+information_schema",
            r"SELECT\s+.*\s+FROM\s+mysql\.",
            r"SLEEP\(",
            r"BENCHMARK\(",
            r"WAITFOR\s+DELAY",
            r"OR\s+1=1",
            r"GROUP\s+BY\s+.*\s+HAVING",
        ],
        "weight": 0.95,
    },
    "xss_attack": {
        "patterns": [r"<script>", r"javascript:", r"onerror=", r"onload="],
        "weight": 0.90,
    },
    "threat_intel": {
        "patterns": [
            r"listed by domain",
            r"blacklist",
            r"blocklist",
            r"denied by policy",
        ],
        "weight": 0.80,
    },
    "spam_activity": {
        "patterns": [
            r"\[SPAM\]",
            r"blocked as spam",
            r"spam score exceeded",
        ],
        "weight": 0.60,
    }
}


def detect_attack_type(message: str) -> tuple[str, float]:
    best_attack = "safe"
    best_confidence = 0.0
    for attack_type, config in ATTACK_PATTERNS.items():
        for pattern in config["patterns"]:
            if re.search(pattern, message, re.IGNORECASE):
                if config["weight"] > best_confidence:
                    best_attack = attack_type
                    best_confidence = config["weight"]
    return best_attack, best_confidence


app = FastAPI(title="Cyber Chakshu SIEM API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    print("Starting Cyber Chakshu SIEM API...")
    if os.environ.get("OPENROUTER_API_KEY"):
        print(f"SOC Analyst AI: OpenRouter configured with model {_soc_model}")
        if _get_soc_client():
            print("[OK] SOC Analyst AI ready")
    else:
        print("SOC Analyst AI: API key missing, using rule-based fallback")


@app.get("/")
async def root():
    return {"status": "ok", "name": "Cyber Chakshu SIEM API"}


@app.post("/parse")
async def parse_logs(
    content: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    forceType: Optional[str] = Form(None),
):
    if file:
        content = (await file.read()).decode("utf-8", errors="ignore")
    if not content:
        raise HTTPException(status_code=400, detail="No content")

    if PARSERS_AVAILABLE:
        result = auto_parse(content, forceType)
        entries = result.get("entries", [])
        
        # 1. Rule-based detection (keywords)
        for entry in entries:
            a_type, conf = detect_attack_type(entry.get("message", ""))
            if a_type != "safe":
                entry["attackType"] = a_type
                entry["attackConfidence"] = conf
                entry["severity"] = "warning"
        
        # 2. ML-based detection (Classification + Anomaly Detection)
        try:
            from ml.classifier import enrich_entries_with_attacks
            entries = enrich_entries_with_attacks(entries)
        except Exception as e:
            print(f"ML enrichment failed: {e}")

        # 3. Generate alerts
        alerts = run_detections(entries) if run_detections else []
        
        # Add anomaly-specific alerts
        for entry in entries:
            if entry.get("isAnomaly") and not any(a["id"] == entry["id"] for a in alerts):
                alerts.append({
                    "id": entry.get("id"),
                    "type": "anomaly",
                    "title": "Behavioral Anomaly Detected",
                    "description": f"Unusual pattern detected in {entry.get('logType')} log (score: {entry.get('anomalyScore', 0):.2f})",
                    "severity": "medium",
                    "confidence": f"{entry.get('attackConfidence', 0.5)*100:.0f}%",
                    "message": entry.get("message", "Behavioral outlier"),
                    "sourceIps": [entry.get("source", {}).get("ip")] if entry.get("source", {}).get("ip") else [],
                    "timestamp": entry.get("timestamp"),
                    "entry": entry,
                })

        return {
            "success": True,
            "detectedType": result.get("detectedType", "unknown"),
            "entries": entries,
            "alerts": alerts,
            "stats": result.get("stats", {}),
            "attackSummary": {
                "totalAttacks": len([e for e in entries if e.get("attackType") and e["attackType"] != "safe"]),
                "totalAnomalies": len([e for e in entries if e.get("isAnomaly")]),
                "attackTypes": list(
                    set(e["attackType"] for e in entries if e.get("attackType") and e["attackType"] != "safe")
                ),
                "riskScore": min(
                    (len([e for e in entries if e.get("attackType") and e["attackType"] != "safe"]) * 10) + 
                    (len([e for e in entries if e.get("isAnomaly")]) * 5), 
                    100
                ),
            },
        }
    return {"success": False, "detail": "Parsers not available"}


@app.post("/parse/chunked")
async def parse_logs_chunked(request: ChunkedParseRequest):
    """Handle combined chunks for large file parsing"""
    if not request.chunks:
        raise HTTPException(status_code=400, detail="No chunks provided")
    
    content = "".join(request.chunks)
    if not content:
        raise HTTPException(status_code=400, detail="Combined content is empty")
        
    if PARSERS_AVAILABLE:
        result = auto_parse(content, request.forceType)
        entries = result.get("entries", [])
        
        for entry in entries:
            a_type, conf = detect_attack_type(entry.get("message", ""))
            if a_type != "safe":
                entry["attackType"] = a_type
                entry["attackConfidence"] = conf
                entry["severity"] = "warning"
        
        try:
            entries = enrich_entries_with_attacks(entries)
        except Exception as e:
            print(f"ML enrichment failed: {e}")

        alerts = run_detections(entries) if run_detections else []
        for entry in entries:
            if entry.get("isAnomaly") and not any(a["id"] == entry["id"] for a in alerts):
                alerts.append({
                    "id": entry.get("id"),
                    "type": "anomaly",
                    "title": "Behavioral Anomaly Detected",
                    "description": f"Unusual pattern detected in {entry.get('logType')} log (score: {entry.get('anomalyScore', 0):.2f})",
                    "severity": "medium",
                    "confidence": f"{entry.get('attackConfidence', 0.5)*100:.0f}%",
                    "message": entry.get("message", "Behavioral outlier"),
                    "sourceIps": [entry.get("source", {}).get("ip")] if entry.get("source", {}).get("ip") else [],
                    "timestamp": entry.get("timestamp"),
                    "entry": entry,
                })

        return {
            "success": True,
            "detectedType": result.get("detectedType", "unknown"),
            "entries": entries,
            "alerts": alerts,
            "stats": result.get("stats", {}),
            "attackSummary": {
                "totalAttacks": len([e for e in entries if e.get("attackType") and e["attackType"] != "safe"]),
                "totalAnomalies": len([e for e in entries if e.get("isAnomaly")]),
                "attackTypes": list(set(e["attackType"] for e in entries if e.get("attackType") and e["attackType"] != "safe")),
                "riskScore": min((len([e for e in entries if e.get("attackType") and e["attackType"] != "safe"]) * 10) + (len([e for e in entries if e.get("isAnomaly")]) * 5), 100),
            },
        }
    return {"success": False, "detail": "Parsers not available"}


@app.post("/correlate")
async def correlate_logs(
    request: Request,
    files: Optional[List[UploadFile]] = File(None),
):
    """
    Parse multiple log files and correlate events between them.
    Handles both multipart/form-data and application/json.
    """
    if not PARSERS_AVAILABLE:
        raise HTTPException(status_code=503, detail="Parsers not available")

    all_entries = []
    sources = []

    content_type = request.headers.get("content-type", "")

    if "application/json" in content_type:
        try:
            body = await request.json()
            # Handle the format: { "logs": [{ "name": "...", "content": "..." }] }
            logs = body.get("logs", [])
            for log in logs:
                name = log.get("name", "unknown")
                content = log.get("content", "")
                if content:
                    result = auto_parse(content)
                    entries = result.get("entries", [])
                    for entry in entries:
                        entry["logSource"] = name
                    all_entries.extend(entries)
                    sources.append({"name": name, "entryCount": len(entries)})
        except Exception as e:
            print(f"JSON correlation failed: {e}")
            raise HTTPException(status_code=400, detail=f"Invalid JSON payload: {str(e)}")

    elif "multipart/form-data" in content_type:
        if not files:
            form = await request.form()
            files = form.getlist("files")
            
        if files:
            for file in files:
                if isinstance(file, str): continue
                content = (await file.read()).decode("utf-8", errors="ignore")
                result = auto_parse(content)
                entries = result.get("entries", [])
                for entry in entries:
                    entry["logSource"] = file.filename
                all_entries.extend(entries)
                sources.append({"name": file.filename, "entryCount": len(entries)})
    
    if not all_entries and not sources:
        raise HTTPException(status_code=400, detail="No logs provided via files or JSON body")

    if not all_entries:
        return {
            "success": True, 
            "sources": sources, 
            "totalEvents": 0, 
            "correlation": {"attackChains": [], "summary": {"riskScore": 0, "totalChains": 0}}, 
            "traditionalAlerts": [],
            "stats": {}
        }

    # Process detection on the combined batch
    for entry in all_entries:
        a_type, conf = detect_attack_type(entry.get("message", ""))
        if a_type != "safe":
            entry["attackType"] = a_type
            entry["attackConfidence"] = conf
            entry["severity"] = "warning"

    try:
        all_entries = enrich_entries_with_attacks(all_entries)
    except Exception as e:
        print(f"ML enrichment failed during correlation: {e}")

    # Run engines
    correlation_result = correlate_events(all_entries)
    alerts = run_detections(all_entries)

    return {
        "success": True,
        "sources": sources,
        "totalEvents": len(all_entries),
        "correlation": correlation_result,
        "traditionalAlerts": alerts,
        "stats": gen_stats(all_entries) if gen_stats else {},
    }


@app.post("/train-anomaly")
async def train_anomaly(
    content: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    forceType: Optional[str] = Form(None),
):
    """Train the anomaly detector on a 'normal' baseline of logs"""
    if file:
        content = (await file.read()).decode("utf-8", errors="ignore")
    if not content:
        raise HTTPException(status_code=400, detail="No content")

    if PARSERS_AVAILABLE:
        result = auto_parse(content, forceType)
        entries = result.get("entries", [])
        
        if len(entries) < 20:
            return {"success": False, "detail": "Need at least 20 log entries to train a baseline"}
            
        try:
            from ml.classifier import train_anomaly_detector
            train_anomaly_detector(entries)
            return {"success": True, "detail": f"Anomaly detector trained on {len(entries)} normal entries"}
        except Exception as e:
            return {"success": False, "detail": f"Training failed: {str(e)}"}
            
    return {"success": False, "detail": "Parsers not available"}


@app.post("/generate-report")
async def generate_siem_report(request: ReportRequest):
    try:
        client = _get_soc_client()
        llm_analysis = None

        # Generate LLM analysis if available
        if client:
            entries = request.data.get("entries", [])[:100] if request.data else []
            alerts = request.data.get("alerts", [])[:50] if request.data else []
            stats = request.data.get("stats", {}) if request.data else {}

            analysis_prompt = f"""You are a senior SOC analyst generating a comprehensive security report. Analyze the following log data and provide:

1. EXECUTIVE SUMMARY: A 2-3 sentence overview of the security posture
2. KEY FINDINGS: List the top 5 security findings with severity levels
3. ATTACK CHAIN ANALYSIS: Describe any detected attack patterns and their kill chain stages
4. THREAT INTELLIGENCE: IOCs, suspicious IPs, attacker TTPs
5. RISK ASSESSMENT: Current risk level (LOW/MEDIUM/HIGH/CRITICAL) with justification
6. RECOMMENDATIONS: Prioritized list of 5-7 actionable security improvements
7. INCIDENT RESPONSE: Suggested response procedures for detected threats

Log Statistics:
- Total Logs: {stats.get("total", "N/A")}
- By Severity: {stats.get("bySeverity", {})}
- By Type: {stats.get("byType", {})}
- Top Sources: {stats.get("topSources", [])[:5]}

Alerts ({len(alerts)} total):
{chr(10).join([f"- {a.get('type', 'Unknown')}: {a.get('message', '')[:100]}" for a in alerts[:20]])}

Sample Log Entries:
{chr(10).join([f"[{e.get('severity', 'info').upper()}] {e.get('timestamp', 'N/A')} - {e.get('message', '')[:150]}" for e in entries[:30]])}

Provide a detailed, professional security report suitable for CISOs and security teams. Use proper security terminology and MITRE ATT&CK framework where applicable."""

            try:
                llm_analysis = client.chat(
                    "Generate a comprehensive SIEM security analysis report",
                    analysis_prompt,
                )
            except Exception as e:
                print(f"LLM analysis failed: {e}")

        reports_dir = os.path.join(os.path.dirname(__file__), "reports")
        os.makedirs(reports_dir, exist_ok=True)
        filename = f"siem_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        output_path = os.path.join(reports_dir, filename)
        SIEMPDFReport(output_path, request.data, llm_analysis).generate()
        return FileResponse(
            output_path, media_type="application/pdf", filename=filename
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/soc-analyze")
async def soc_analyze(request: LogAnalysisRequest):
    client = _get_soc_client()
    if not client:
        return {"analysis": "Rule-based: " + request.log_entry[:50]}
    analysis = client.chat("Analyze log", request.log_entry)
    return {
        "analysis": analysis,
        "attack_detected": "attack" in analysis.lower(),
        "severity": "medium",
    }


@app.post("/soc-chat")
async def soc_chat(request: ChatRequest):
    client = _get_soc_client()

    # Enhanced context building - include actual log entries for analysis
    analysis_knowledge = ""
    if request.analysis_context:
        ctx = request.analysis_context
        analysis_knowledge = f"""Current Log Analysis Context:
- Detected Log Type: {ctx.get("detectedType", "unknown")}
- Total Log Lines: {ctx.get("totalLines", 0)}
- Parsed Successfully: {ctx.get("parsedLines", 0)}

"""
        # Include sample log entries for the SOC Analyst to analyze
        entries = ctx.get("entries", [])
        if entries and len(entries) > 0:
            # Include up to 50 sample entries for context
            sample_entries = entries[:50]
            entries_text = "\n".join(
                [
                    f"[{entry.get('timestamp', 'N/A')}] {entry.get('severity', 'info').upper()} - {entry.get('message', '')[:200]}"
                    for entry in sample_entries
                ]
            )
            analysis_knowledge += f"""Recent Log Entries (first {len(sample_entries)} of {len(entries)}):
{entries_text}

"""

        # Include attack information if available
        attack_summary = ctx.get("attackSummary", {})
        if attack_summary:
            analysis_knowledge += f"""Attack Detection Summary:
- Total Attacks Detected: {attack_summary.get("totalAttacks", 0)}
- Attack Types: {", ".join(attack_summary.get("attackTypes", []))}

"""

    if not client:
        return {"response": "AI Unavailable. " + analysis_knowledge}

    response = client.chat(
        "You are a SOC Analyst. Use the log entries provided above to answer questions about security events, attack patterns, and anomalies.",
        analysis_knowledge + request.message,
    )
    return {"response": response}


@app.get("/forensics/health")
async def forensics_health():
    return {
        "status": "ok",
        "pipeline_available": FORENSIC_PIPELINE_AVAILABLE,
        "api_key_configured": bool(os.environ.get("OPENROUTER_API_KEY")),
    }


@app.post("/forensics/start")
async def start_forensic_analysis(request: ForensicStartRequest):
    if not FORENSIC_PIPELINE_AVAILABLE:
        raise HTTPException(status_code=503, detail="Forensic pipeline not available")

    image_path = request.image_path.strip()
    if not os.path.exists(image_path):
        raise HTTPException(status_code=400, detail="Image file not found")

    task = task_manager.create_task(image_path)
    thread = threading.Thread(
        target=task_manager.run_forensic_analysis, args=(task.task_id, image_path)
    )
    thread.daemon = True
    thread.start()

    return {
        "task_id": task.task_id,
        "status": task.status.value,
        "message": "Forensic analysis started",
    }


@app.get("/forensics/status/{task_id}")
async def get_forensic_status(task_id: str):
    task = task_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return {
        "task_id": task.task_id,
        "status": task.status.value,
        "progress": task.progress,
        "stage": task.stage,
        "message": task.message,
    }


@app.get("/forensics/results/{task_id}")
async def get_forensic_results(task_id: str):
    task = task_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.status != TaskStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Task not completed")
    return {
        "task_id": task.task_id,
        "results": task.results,
        "summary": task.results.get("summary", ""),
        "risk_level": task.results.get("risk_level", "UNKNOWN"),
    }


@app.get("/forensics/pdf/{task_id}")
async def download_forensic_pdf(task_id: str):
    task = task_manager.get_task(task_id)
    if not task or not task.pdf_path:
        raise HTTPException(status_code=404)
    return FileResponse(
        task.pdf_path,
        media_type="application/pdf",
        filename=os.path.basename(task.pdf_path),
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8788)
