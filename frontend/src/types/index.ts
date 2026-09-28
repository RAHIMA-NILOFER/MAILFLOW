export type Protocol = 'SMTP' | 'IMAP' | 'POP3';
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type SessionStatus = 'ENCRYPTED' | 'PLAINTEXT' | 'DOWNGRADED' | 'FAILED_HANDSHAKE';

export interface CommunicationStep {
  step_number: number;
  sender: 'Client' | 'Server';
  protocol_layer: string;
  command_or_status: string;
  is_encrypted: boolean;
  timestamp_offset_ms: number;
  description: string;
  raw_payload_snippet?: string;
}

export interface TLSHandshake {
  session_id: string;
  tls_version: string;
  cipher_suite: string;
  cipher_suite_hex?: string;
  key_exchange: string;
  authentication: string;
  encryption_algorithm: string;
  mac_hash: string;
  forward_secrecy: boolean;
  session_resumption: boolean;
  alpn?: string;
  sni_server_name?: string;
  client_supported_versions: string[];
  extensions: string[];
  warnings: string[];
  risk: string;
}

export interface Certificate {
  id: string;
  session_id: string;
  subject_cn: string;
  subject_o?: string;
  subject_ou?: string;
  issuer_cn: string;
  issuer_o?: string;
  serial_number: string;
  fingerprint_sha256: string;
  valid_from: string;
  valid_until: string;
  days_remaining: number;
  public_key_algorithm: string;
  key_length: number;
  signature_algorithm: string;
  san_list: string[];
  chain_status: string;
  trust_status: string;
  is_self_signed: boolean;
  is_expired: boolean;
  is_expiring_soon: boolean;
  chain_visualization: Array<{
    tier: string;
    cn: string;
    status: string;
    is_leaf: boolean;
  }>;
  validation_checks: Record<string, boolean>;
  warnings: string[];
  risk: string;
}

export interface EmailSession {
  session_id: string;
  protocol: Protocol;
  source_ip: string;
  source_port: number;
  dest_ip: string;
  dest_port: number;
  client_hostname?: string;
  server_banner?: string;
  starttls_requested: boolean;
  starttls_success: boolean;
  tls_version?: string;
  cipher_suite?: string;
  certificate_subject?: string;
  certificate_id?: string;
  risk: Severity;
  status: SessionStatus;
  start_time: string;
  end_time: string;
  duration_ms: number;
  packet_count: number;
  byte_count: number;
  communication_flow: CommunicationStep[];
  flags: string[];
  explainable_risk_factors: string[];
  risk_score: number;
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  session_id: string;
  protocol: string;
  evidence_observed: string;
  expected_secure: string;
  evidence_detail: string;
  packet_stream_ref: string;
  impact: string;
  recommendation: string;
  cwe_id?: string;
  cvss_score?: number;
  status: string;
}

export interface Anomaly {
  id: string;
  anomaly_type: string;
  session_id: string;
  protocol: string;
  anomaly_score: number;
  confidence: string;
  severity: Severity;
  evidence: string;
  explanation: string;
  timestamp: string;
}

export interface RiskFeatureContribution {
  feature_name: string;
  contribution_points: number;
  description: string;
  category: string;
}

export interface RiskAssessment {
  overall_risk_score: number;
  posture_rating: string;
  cryptographic_risk: number;
  certificate_risk: number;
  protocol_risk: number;
  tls_anomaly_risk: number;
  configuration_risk: number;
  feature_contributions: RiskFeatureContribution[];
  top_risk_drivers: string[];
  model_version: string;
}

export interface ThreatMatrixItem {
  finding_id: string;
  title: string;
  severity: Severity;
  impact_score: number;
  likelihood_score: number;
  exploitability: string;
  exposure: string;
  affected_sessions_count: number;
  confidence: string;
}

export interface SecurityPosture {
  overall_score: number;
  previous_score?: number;
  change: number;
  breakdown: Record<string, number>;
  top_recommended_actions: Array<{
    priority: number;
    title: string;
    action: string;
    effort: string;
    impact: string;
  }>;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  session_id: string;
  protocol: string;
  event_type: string;
  severity: string;
  title: string;
  description: string;
  source_ip: string;
  dest_ip: string;
  details?: Record<string, any>;
}

export interface PCAPAnalysis {
  id: string;
  filename: string;
  file_size_bytes: number;
  file_size_formatted: string;
  sha256_hash: string;
  upload_timestamp: string;
  analysis_duration_seconds: number;
  is_demo: boolean;
  status: string;
  total_packets: number;
  total_email_sessions: number;
  total_tls_sessions: number;
  total_starttls_sessions: number;
  total_certificates: number;
  critical_findings_count: number;
  high_findings_count: number;
  medium_findings_count: number;
  low_findings_count: number;
  security_score: number;
  protocol_distribution: {
    smtp: number;
    imap: number;
    pop3: number;
  };
  tls_version_distribution: {
    tls13: number;
    tls12: number;
    tls11: number;
    tls10: number;
    ssl_unknown: number;
  };
  risk_distribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  crypto_weakness_stats: {
    deprecated_tls: number;
    weak_cipher: number;
    cert_expired: number;
    cert_misconfig: number;
    missing_pfs: number;
    weak_key: number;
    insecure_sig_alg: number;
    insecure_starttls: number;
  };
  sessions: EmailSession[];
  tls_handshakes: TLSHandshake[];
  certificates: Certificate[];
  findings: Finding[];
  anomalies: Anomaly[];
  timeline: TimelineEvent[];
  risk_assessment?: RiskAssessment;
  threat_matrix: ThreatMatrixItem[];
  security_posture?: SecurityPosture;
}
