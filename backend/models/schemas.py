"""
Pydantic Data Models for MailFlow Sentinel
Passive Email Cryptographic Forensics & AI-Assisted Risk Analysis
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class ProtocolDistribution(BaseModel):
    smtp: int = 0
    imap: int = 0
    pop3: int = 0

class TLSVersionDistribution(BaseModel):
    tls13: int = 0
    tls12: int = 0
    tls11: int = 0
    tls10: int = 0
    ssl_unknown: int = 0

class RiskDistribution(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

class CryptoWeaknessStats(BaseModel):
    deprecated_tls: int = 0
    weak_cipher: int = 0
    cert_expired: int = 0
    cert_misconfig: int = 0
    missing_pfs: int = 0
    weak_key: int = 0
    insecure_sig_alg: int = 0
    insecure_starttls: int = 0

class TimelineEvent(BaseModel):
    id: str
    timestamp: str
    session_id: str
    protocol: str
    event_type: str
    severity: str # critical, high, medium, low, info
    title: str
    description: str
    source_ip: str
    dest_ip: str
    details: Optional[Dict[str, Any]] = None

class CommunicationStep(BaseModel):
    step_number: int
    sender: str # "Client" or "Server"
    protocol_layer: str # "TCP", "SMTP/IMAP/POP3", "TLS"
    command_or_status: str
    is_encrypted: bool = False
    timestamp_offset_ms: float = 0.0
    description: str = ""
    raw_payload_snippet: Optional[str] = None

class TLSHandshake(BaseModel):
    session_id: str
    tls_version: str # TLS 1.3, TLS 1.2, TLS 1.1, TLS 1.0, SSL 3.0, None
    cipher_suite: str
    cipher_suite_hex: Optional[str] = None
    key_exchange: str = "Unknown"
    authentication: str = "Unknown"
    encryption_algorithm: str = "Unknown"
    mac_hash: str = "Unknown"
    forward_secrecy: bool = True
    session_resumption: bool = False
    alpn: Optional[str] = None
    sni_server_name: Optional[str] = None
    client_supported_versions: List[str] = Field(default_factory=list)
    extensions: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    risk: str = "LOW" # LOW, MEDIUM, HIGH, CRITICAL

class Certificate(BaseModel):
    id: str
    session_id: str
    subject_cn: str
    subject_o: Optional[str] = None
    subject_ou: Optional[str] = None
    issuer_cn: str
    issuer_o: Optional[str] = None
    serial_number: str
    fingerprint_sha256: str
    valid_from: str
    valid_until: str
    days_remaining: int
    public_key_algorithm: str # RSA, ECDSA, Ed25519
    key_length: int # 2048, 4096, 1024, 256
    signature_algorithm: str
    san_list: List[str] = Field(default_factory=list)
    chain_status: str = "COMPLETE"
    trust_status: str = "TRUSTED_ROOT"
    is_self_signed: bool = False
    is_expired: bool = False
    is_expiring_soon: bool = False
    chain_visualization: List[Dict[str, Any]] = Field(default_factory=list)
    validation_checks: Dict[str, bool] = Field(default_factory=dict)
    warnings: List[str] = Field(default_factory=list)
    risk: str = "LOW" # LOW, MEDIUM, HIGH, CRITICAL

class EmailSession(BaseModel):
    session_id: str
    protocol: str # "SMTP", "IMAP", "POP3"
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    client_hostname: Optional[str] = None
    server_banner: Optional[str] = None
    starttls_requested: bool = False
    starttls_success: bool = False
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    certificate_subject: Optional[str] = None
    certificate_id: Optional[str] = None
    risk: str = "LOW"
    status: str = "ENCRYPTED"
    start_time: str
    end_time: str
    duration_ms: int = 0
    packet_count: int = 0
    byte_count: int = 0
    communication_flow: List[CommunicationStep] = Field(default_factory=list)
    flags: List[str] = Field(default_factory=list)
    explainable_risk_factors: List[str] = Field(default_factory=list)
    risk_score: int = 15

class Finding(BaseModel):
    id: str
    title: str
    severity: str
    category: str
    session_id: str
    protocol: str
    evidence_observed: str
    expected_secure: str
    evidence_detail: str
    packet_stream_ref: str
    impact: str
    recommendation: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    status: str = "OPEN"

class Anomaly(BaseModel):
    id: str
    anomaly_type: str
    session_id: str
    protocol: str
    anomaly_score: int = 0
    confidence: str = "HIGH"
    severity: str = "MEDIUM"
    evidence: str = ""
    explanation: str = ""
    timestamp: str = ""

class RiskFeatureContribution(BaseModel):
    feature_name: str
    contribution_points: int
    description: str
    category: str

class RiskAssessment(BaseModel):
    overall_risk_score: int = 0
    posture_rating: str = "Moderate"
    cryptographic_risk: int = 0
    certificate_risk: int = 0
    protocol_risk: int = 0
    tls_anomaly_risk: int = 0
    configuration_risk: int = 0
    feature_contributions: List[RiskFeatureContribution] = Field(default_factory=list)
    top_risk_drivers: List[str] = Field(default_factory=list)
    model_version: str = "Sentinel-RiskEngine-v2.4 (Explainable ML Rule Hybrid)"

class ThreatMatrixItem(BaseModel):
    finding_id: str
    title: str
    severity: str
    impact_score: int = 1
    likelihood_score: int = 1
    exploitability: str = "MEDIUM"
    exposure: str = "EXTERNAL"
    affected_sessions_count: int = 1
    confidence: str = "HIGH"

def default_breakdown() -> Dict[str, int]:
    return {
        "protocol_security": 85,
        "tls_configuration": 78,
        "certificate_security": 80,
        "cryptographic_strength": 75,
        "forward_secrecy": 90,
        "starttls_security": 82,
        "configuration_hygiene": 88
    }

class SecurityPosture(BaseModel):
    overall_score: int = 80
    previous_score: Optional[int] = 74
    change: int = 8
    breakdown: Dict[str, int] = Field(default_factory=default_breakdown)
    top_recommended_actions: List[Dict[str, Any]] = Field(default_factory=list)

class PCAPAnalysis(BaseModel):
    id: str
    filename: str
    file_size_bytes: int = 0
    file_size_formatted: str = "0 KB"
    sha256_hash: str = ""
    upload_timestamp: str = ""
    analysis_duration_seconds: float = 0.0
    is_demo: bool = False
    status: str = "COMPLETED"
    
    # Counts
    total_packets: int = 0
    total_email_sessions: int = 0
    total_tls_sessions: int = 0
    total_starttls_sessions: int = 0
    total_certificates: int = 0
    critical_findings_count: int = 0
    high_findings_count: int = 0
    medium_findings_count: int = 0
    low_findings_count: int = 0
    security_score: int = 0
    
    # Distributions
    protocol_distribution: ProtocolDistribution = Field(default_factory=ProtocolDistribution)
    tls_version_distribution: TLSVersionDistribution = Field(default_factory=TLSVersionDistribution)
    risk_distribution: RiskDistribution = Field(default_factory=RiskDistribution)
    crypto_weakness_stats: CryptoWeaknessStats = Field(default_factory=CryptoWeaknessStats)
    
    # Collections
    sessions: List[EmailSession] = Field(default_factory=list)
    tls_handshakes: List[TLSHandshake] = Field(default_factory=list)
    certificates: List[Certificate] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    anomalies: List[Anomaly] = Field(default_factory=list)
    timeline: List[TimelineEvent] = Field(default_factory=list)
    risk_assessment: Optional[RiskAssessment] = None
    threat_matrix: List[ThreatMatrixItem] = Field(default_factory=list)
    security_posture: Optional[SecurityPosture] = None
