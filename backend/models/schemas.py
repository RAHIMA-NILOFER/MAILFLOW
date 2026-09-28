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
    command_or_status: str # e.g. "SYN", "220 mail.corp.net ESMTP", "EHLO sentinel.net", "STARTTLS", "220 2.0.0 Ready to start TLS", "ClientHello (TLS 1.3)", "ServerHello + Certificate + Finished", "Encrypted Handshake"
    is_encrypted: bool = False
    timestamp_offset_ms: float
    description: str
    raw_payload_snippet: Optional[str] = None

class TLSHandshake(BaseModel):
    session_id: str
    tls_version: str # TLS 1.3, TLS 1.2, TLS 1.1, TLS 1.0, SSL 3.0, None
    cipher_suite: str # e.g. "TLS_AES_256_GCM_SHA384", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    cipher_suite_hex: Optional[str] = None
    key_exchange: str # e.g. "ECDHE (X25519)", "RSA", "DHE"
    authentication: str # e.g. "RSA-PSS", "ECDSA", "RSA"
    encryption_algorithm: str # e.g. "AES-256-GCM", "3DES-CBC", "ChaCha20-Poly1305"
    mac_hash: str # e.g. "SHA384", "SHA1", "AEAD"
    forward_secrecy: bool = True
    session_resumption: bool = False
    alpn: Optional[str] = None # e.g. "smtp", "imap"
    sni_server_name: Optional[str] = None
    client_supported_versions: List[str] = []
    extensions: List[str] = []
    warnings: List[str] = []
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
    signature_algorithm: str # sha256WithRSAEncryption, sha1WithRSAEncryption, md5WithRSAEncryption
    san_list: List[str] = []
    chain_status: str # "COMPLETE", "INCOMPLETE", "BROKEN", "SELF_SIGNED"
    trust_status: str # "TRUSTED_ROOT", "INTERNAL_CA", "UNTRUSTED", "EXPIRED", "REVOKED_UNKNOWN"
    is_self_signed: bool = False
    is_expired: bool = False
    is_expiring_soon: bool = False
    chain_visualization: List[Dict[str, Any]] = [] # [Root CA, Intermediate CA, Server Cert]
    validation_checks: Dict[str, bool] = {}
    warnings: List[str] = []
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
    risk: str = "LOW" # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    status: str = "ENCRYPTED" # "ENCRYPTED", "PLAINTEXT", "DOWNGRADED", "FAILED_HANDSHAKE"
    start_time: str
    end_time: str
    duration_ms: int
    packet_count: int
    byte_count: int
    communication_flow: List[CommunicationStep] = []
    flags: List[str] = []
    explainable_risk_factors: List[str] = []
    risk_score: int = 15

class Finding(BaseModel):
    id: str # e.g. "CRYPTO-001"
    title: str
    severity: str # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    category: str # "TLS Configuration", "Cipher Suite", "Certificate", "STARTTLS", "Key Exchange", "Signature"
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
    status: str = "OPEN" # "OPEN", "RESOLVED", "ACCEPTED"

class Anomaly(BaseModel):
    id: str
    anomaly_type: str # "Unexpected TLS Downgrade", "Rare Cipher Suite", "Abnormal Handshake Sequence", "Certificate Hostname Mismatch", "Plaintext Credentials Before STARTTLS"
    session_id: str
    protocol: str
    anomaly_score: int # 0 to 100
    confidence: str # "HIGH", "MEDIUM", "LOW"
    severity: str # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    evidence: str
    explanation: str
    timestamp: str

class RiskFeatureContribution(BaseModel):
    feature_name: str
    contribution_points: int
    description: str
    category: str

class RiskAssessment(BaseModel):
    overall_risk_score: int # 0 to 100
    posture_rating: str # "Excellent", "Good", "Moderate", "Poor", "Critical"
    cryptographic_risk: int # 0 to 100
    certificate_risk: int # 0 to 100
    protocol_risk: int # 0 to 100
    tls_anomaly_risk: int # 0 to 100
    configuration_risk: int # 0 to 100
    feature_contributions: List[RiskFeatureContribution] = []
    top_risk_drivers: List[str] = []
    model_version: str = "Sentinel-RiskEngine-v2.4 (Explainable ML Rule Hybrid)"

class ThreatMatrixItem(BaseModel):
    finding_id: str
    title: str
    severity: str
    impact_score: int # 1 to 5
    likelihood_score: int # 1 to 5
    exploitability: str # "HIGH", "MEDIUM", "LOW"
    exposure: str # "EXTERNAL", "INTERNAL", "TRANSIT"
    affected_sessions_count: int
    confidence: str

class SecurityPosture(BaseModel):
    overall_score: int # 0 to 100 (e.g. 82)
    previous_score: Optional[int] = 74
    change: int = 8
    breakdown: Dict[str, int] = {
        "protocol_security": 85,
        "tls_configuration": 78,
        "certificate_security": 80,
        "cryptographic_strength": 75,
        "forward_secrecy": 90,
        "starttls_security": 82,
        "configuration_hygiene": 88
    }
    top_recommended_actions: List[Dict[str, Any]] = []

class PCAPAnalysis(BaseModel):
    id: str
    filename: str
    file_size_bytes: int
    file_size_formatted: str
    sha256_hash: str
    upload_timestamp: str
    analysis_duration_seconds: float
    is_demo: bool = False
    status: str = "COMPLETED"
    
    # Counts
    total_packets: int
    total_email_sessions: int
    total_tls_sessions: int
    total_starttls_sessions: int
    total_certificates: int
    critical_findings_count: int
    high_findings_count: int
    medium_findings_count: int
    low_findings_count: int
    security_score: int
    
    # Distributions
    protocol_distribution: ProtocolDistribution
    tls_version_distribution: TLSVersionDistribution
    risk_distribution: RiskDistribution
    crypto_weakness_stats: CryptoWeaknessStats
    
    # Collections
    sessions: List[EmailSession] = []
    tls_handshakes: List[TLSHandshake] = []
    certificates: List[Certificate] = []
    findings: List[Finding] = []
    anomalies: List[Anomaly] = []
    timeline: List[TimelineEvent] = []
    risk_assessment: Optional[RiskAssessment] = None
    threat_matrix: List[ThreatMatrixItem] = []
    security_posture: Optional[SecurityPosture] = None
