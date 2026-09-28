"""
MailFlow Sentinel - Backend REST API Server
FastAPI Application implementing all Passive Email Forensic Analysis Endpoints.
"""
import os
import tempfile
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response

from backend.models.schemas import (
    PCAPAnalysis, EmailSession, TLSHandshake, Certificate,
    Finding, Anomaly, RiskAssessment, SecurityPosture, ThreatMatrixItem
)
from backend.services.pcap_service import (
    get_or_create_demo_analysis,
    get_analysis_by_id,
    process_uploaded_pcap,
    ANALYSIS_STORE
)
from backend.reports.report_generator import generate_html_report

app = FastAPI(
    title="MailFlow Sentinel API",
    description="Passive Email Cryptographic Forensics & AI-Assisted Risk Analysis Platform",
    version="2.4.0"
)

# Enable CORS for local Vite dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
def health_check():
    return {
        "status": "ONLINE",
        "service": "MailFlow Sentinel Backend",
        "version": "2.4.0",
        "mode": "DEFENSIVE_PASSIVE_FORENSIC"
    }

@app.post("/api/pcap/upload")
async def upload_pcap(file: UploadFile = File(...)):
    """Upload PCAP / PCAPNG file for passive forensic processing."""
    if not file.filename.endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(
            status_code=400,
            detail="Unsupported file format. Please upload a .pcap, .pcapng, or .cap packet capture file."
        )
    
    # Save uploaded file to temp file
    suffix = os.path.splitext(file.filename)[1]
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_pcap:
        contents = await file.read()
        temp_pcap.write(contents)
        temp_pcap_path = temp_pcap.name

    try:
        analysis = process_uploaded_pcap(temp_pcap_path, file.filename)
        return {
            "status": "SUCCESS",
            "message": "PCAP parsed and analyzed successfully",
            "analysis_id": analysis.id,
            "filename": analysis.filename,
            "total_packets": analysis.total_packets,
            "total_email_sessions": analysis.total_email_sessions,
            "security_score": analysis.security_score
        }
    finally:
        if os.path.exists(temp_pcap_path):
            try:
                os.remove(temp_pcap_path)
            except Exception:
                pass

@app.post("/api/analysis/start")
def start_analysis(analysis_id: Optional[str] = "demo"):
    """Trigger analysis pipeline for a loaded file or return demo analysis."""
    analysis = get_analysis_by_id(analysis_id)
    return {"status": "SUCCESS", "analysis_id": analysis.id, "state": "COMPLETED"}

@app.get("/api/analysis/{analysis_id}")
def get_analysis_overview(analysis_id: str):
    """Retrieve full analysis bundle."""
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis

@app.get("/api/analysis/{analysis_id}/sessions")
def get_analysis_sessions(
    analysis_id: str,
    protocol: Optional[str] = Query(None, description="Filter by SMTP, IMAP, or POP3"),
    risk: Optional[str] = Query(None, description="Filter by risk severity"),
    search: Optional[str] = Query(None, description="Search term for IP, hostname, or session ID")
):
    """Retrieve reconstructed email sessions with filtering and search."""
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
        
    sessions = analysis.sessions
    if protocol and protocol.upper() != "ALL":
        sessions = [s for s in sessions if s.protocol.upper() == protocol.upper()]
    if risk and risk.upper() != "ALL":
        sessions = [s for s in sessions if s.risk.upper() == risk.upper()]
    if search:
        s_lower = search.lower()
        sessions = [
            s for s in sessions
            if s_lower in s.session_id.lower()
            or s_lower in s.source_ip.lower()
            or s_lower in s.dest_ip.lower()
            or (s.client_hostname and s_lower in s.client_hostname.lower())
            or (s.cipher_suite and s_lower in s.cipher_suite.lower())
        ]
    return sessions

@app.get("/api/analysis/{analysis_id}/session/{session_id}")
def get_session_detail(analysis_id: str, session_id: str):
    """Retrieve forensic details and communication flow for a specific session."""
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    for s in analysis.sessions:
        if s.session_id.lower() == session_id.lower():
            return s
    raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

@app.get("/api/analysis/{analysis_id}/tls")
def get_analysis_tls(analysis_id: str):
    """Retrieve TLS handshake metadata and cryptographic parameters."""
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis.tls_handshakes

@app.get("/api/analysis/{analysis_id}/certificates")
def get_analysis_certificates(analysis_id: str):
    """Retrieve X.509 certificates and chain validation checks."""
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis.certificates

@app.get("/api/analysis/{analysis_id}/findings")
def get_analysis_findings(analysis_id: str, severity: Optional[str] = None):
    """Retrieve cryptographic findings and policy violations."""
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    findings = analysis.findings
    if severity and severity.upper() != "ALL":
        findings = [f for f in findings if f.severity.upper() == severity.upper()]
    return findings

@app.get("/api/analysis/{analysis_id}/risk")
def get_analysis_risk(analysis_id: str):
    """Retrieve AI-assisted risk scores and explainable feature contributions."""
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis.risk_assessment

@app.get("/api/analysis/{analysis_id}/anomalies")
def get_analysis_anomalies(analysis_id: str):
    """Retrieve detected TLS and protocol anomalies."""
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis.anomalies

@app.get("/api/analysis/{analysis_id}/posture")
def get_analysis_posture(analysis_id: str):
    """Retrieve overall security posture and prioritized remediation actions."""
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis.security_posture

@app.get("/api/reports/{analysis_id}/json")
def export_report_json(analysis_id: str):
    """Export complete forensic report in JSON format."""
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return JSONResponse(
        content=analysis.model_dump(),
        headers={"Content-Disposition": f'attachment; filename="mailflow_forensic_{analysis.id}.json"'}
    )

@app.get("/api/reports/{analysis_id}/html", response_class=HTMLResponse)
def export_report_html(analysis_id: str):
    """Export complete forensic report in printable / styled HTML format."""
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    html_content = generate_html_report(analysis)
    return HTMLResponse(content=html_content)

@app.get("/api/reports/{analysis_id}/pdf")
def export_report_pdf(analysis_id: str):
    """Generate printable HTML suitable for browser Print-to-PDF."""
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    html_content = generate_html_report(analysis)
    return HTMLResponse(content=html_content)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
