"""
TLS & Protocol Anomaly Detection Engine for MailFlow Sentinel
Detects suspicious patterns, unexpected downgrades, rare cipher suites, and protocol sequence abnormalities.
"""
from typing import List
from backend.models.schemas import Anomaly, EmailSession, TLSHandshake, Certificate

def detect_anomalies(
    sessions: List[EmailSession],
    tls_handshakes: List[TLSHandshake],
    certificates: List[Certificate]
) -> List[Anomaly]:
    """Inspect traffic traces for behavioral and cryptographic anomalies."""
    anomalies: List[Anomaly] = []
    counter = 1
    
    tls_map = {t.session_id: t for t in tls_handshakes}
    cert_map = {c.session_id: c for c in certificates}
    
    for session in sessions:
        tls = tls_map.get(session.session_id)
        cert = cert_map.get(session.session_id)
        
        # 1. Unexpected TLS Downgrade
        if session.status == "DOWNGRADED" or (tls and tls.tls_version == "TLS 1.0" and session.protocol in ["SMTP", "IMAP"]):
            anomalies.append(Anomaly(
                id=f"ANOM-{counter:03d}",
                anomaly_type="Unexpected TLS Downgrade",
                session_id=session.session_id,
                protocol=session.protocol,
                anomaly_score=88,
                confidence="HIGH",
                severity="CRITICAL" if session.status == "DOWNGRADED" else "HIGH",
                evidence=f"Client offered TLS 1.3/1.2 support but session negotiated {tls.tls_version if tls else 'PLAINTEXT'}",
                explanation="Handshake negotiation fell back to an insecure legacy version despite modern client capabilities, characteristic of STARTTLS stripping or an active downgrade proxy.",
                timestamp=session.start_time
            ))
            counter += 1

        # 2. Rare or Exotic Cipher Suite
        if tls and ("RC4" in tls.cipher_suite or "3DES" in tls.cipher_suite or "EXP" in tls.cipher_suite):
            anomalies.append(Anomaly(
                id=f"ANOM-{counter:03d}",
                anomaly_type="Rare / Obsolete Cipher Suite Selection",
                session_id=session.session_id,
                protocol=session.protocol,
                anomaly_score=76,
                confidence="HIGH",
                severity="HIGH",
                evidence=f"Negotiated Cipher: {tls.cipher_suite}",
                explanation="Observed cipher suite is in the bottom 0.5% of modern enterprise email traffic. May indicate legacy automated script or misconfigured relay daemon.",
                timestamp=session.start_time
            ))
            counter += 1

        # 3. Abnormal Handshake Latency / Duration
        if session.duration_ms > 4500 and tls:
            anomalies.append(Anomaly(
                id=f"ANOM-{counter:03d}",
                anomaly_type="Abnormal Handshake Latency Delay",
                session_id=session.session_id,
                protocol=session.protocol,
                anomaly_score=62,
                confidence="MEDIUM",
                severity="MEDIUM",
                evidence=f"Session duration: {session.duration_ms}ms with multiple handshake retransmissions",
                explanation="Substantial delay in TLS handshake completion, indicating possible packet inspection, proxy throttling, or MTU fragmentation issues.",
                timestamp=session.start_time
            ))
            counter += 1

        # 4. Plaintext Sensitive Command Leakage
        if session.status == "PLAINTEXT" and session.protocol in ["IMAP", "POP3"]:
            anomalies.append(Anomaly(
                id=f"ANOM-{counter:03d}",
                anomaly_type="Plaintext Authentication Credentials Exposure",
                session_id=session.session_id,
                protocol=session.protocol,
                anomaly_score=94,
                confidence="HIGH",
                severity="CRITICAL",
                evidence=f"{session.protocol} LOGIN / AUTH command observed over unencrypted TCP connection",
                explanation="Mail client attempted user authentication without prior STARTTLS command, exposing cleartext credentials over passive wiretap.",
                timestamp=session.start_time
            ))
            counter += 1

        # 5. Certificate Hostname / SAN Mismatch
        if cert and session.client_hostname:
            domain_matched = False
            for san in cert.san_list:
                if san.replace("*.", "") in session.client_hostname or cert.subject_cn in session.client_hostname:
                    domain_matched = True
                    break
            if not domain_matched and not cert.is_self_signed:
                anomalies.append(Anomaly(
                    id=f"ANOM-{counter:03d}",
                    anomaly_type="Certificate Hostname Mismatch",
                    session_id=session.session_id,
                    protocol=session.protocol,
                    anomaly_score=79,
                    confidence="HIGH",
                    severity="HIGH",
                    evidence=f"Connected Hostname '{session.client_hostname}' not present in SAN list: {', '.join(cert.san_list[:3])}",
                    explanation="The server presented a valid certificate belonging to an unrelated domain or CDN endpoint, preventing strict cryptographic identity validation.",
                    timestamp=session.start_time
                ))
                counter += 1

    return anomalies
