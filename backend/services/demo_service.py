"""
Realistic Enterprise Demo Data Generator for MailFlow Sentinel
Generates standard enterprise PCAP forensic data:
File: enterprise_mail_capture.pcap
Packets: 48,392 | Sessions: 127 (SMTP: 61, IMAP: 44, POP3: 22) | TLS: 109 | STARTTLS: 103
Findings: 3 Critical, 12 High, 18 Medium | Posture Score: 71/100
"""
from datetime import datetime, timezone, timedelta
from typing import List, Dict
import hashlib
from backend.models.schemas import (
    PCAPAnalysis, EmailSession, TLSHandshake, Certificate,
    Finding, Anomaly, TimelineEvent, CommunicationStep,
    ProtocolDistribution, TLSVersionDistribution, RiskDistribution,
    CryptoWeaknessStats
)
from backend.analyzers.tls_analyzer import analyze_tls_session
from backend.analyzers.cert_analyzer import analyze_certificate_record
from backend.analyzers.crypto_engine import generate_cryptographic_findings
from backend.analyzers.anomaly_detector import detect_anomalies
from backend.analyzers.risk_engine import evaluate_risk_assessment

def generate_demo_analysis() -> PCAPAnalysis:
    """Generate comprehensive, realistic demo forensic data for enterprise_mail_capture.pcap."""
    
    base_time = datetime(2026, 9, 28, 14, 30, 0, tzinfo=timezone.utc)
    
    # 1. Generate Certificates
    certificates: List[Certificate] = [
        analyze_certificate_record(
            cert_id="CERT-001",
            session_id="SMTP-0042",
            subject_cn="mail.enterprise-corp.com",
            issuer_cn="DigiCert Global TLS RSA4096 Root CA",
            serial_number="04:A2:89:C1:90:3B:EE:74:10",
            fingerprint_sha256="7F:8A:1C:99:3B:55:01:E2:DA:44:88:91:AC:5B:33:41:22:90:EE:11:55:77:88:99:AA:BB:CC:DD:EE:FF:00:11",
            valid_from_str="2024-03-01T00:00:00Z",
            valid_until_str="2025-08-15T23:59:59Z", # Expired!
            public_key_alg="RSA",
            key_length=2048,
            sig_alg="sha256WithRSAEncryption",
            san_list=["mail.enterprise-corp.com", "smtp.enterprise-corp.com", "mx1.enterprise-corp.com"],
            is_self_signed=False,
            is_expired_override=True,
            chain_type="COMPLETE"
        ),
        analyze_certificate_record(
            cert_id="CERT-002",
            session_id="SMTP-0015",
            subject_cn="internal-relay.corp.local",
            issuer_cn="internal-relay.corp.local",
            serial_number="18:B9:44:FF:01:23:45:67:89",
            fingerprint_sha256="12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0",
            valid_from_str="2023-01-10T00:00:00Z",
            valid_until_str="2028-01-10T23:59:59Z",
            public_key_alg="RSA",
            key_length=1024, # Weak 1024-bit key
            sig_alg="sha1WithRSAEncryption", # Deprecated SHA-1
            san_list=["internal-relay.corp.local", "mailrelay.local"],
            is_self_signed=True,
            chain_type="SELF_SIGNED"
        ),
        analyze_certificate_record(
            cert_id="CERT-003",
            session_id="IMAP-0008",
            subject_cn="imap.cloudmail-gateway.net",
            issuer_cn="Let's Encrypt Authority E6",
            serial_number="03:FF:11:88:55:22:99:33:AA",
            fingerprint_sha256="CC:44:88:22:11:99:00:55:EE:77:AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF",
            valid_from_str="2026-08-01T00:00:00Z",
            valid_until_str="2026-10-10T23:59:59Z", # Expiring in 12 days!
            public_key_alg="ECDSA",
            key_length=256,
            sig_alg="ecdsa-with-SHA256",
            san_list=["imap.cloudmail-gateway.net", "pop.cloudmail-gateway.net"],
            is_self_signed=False,
            chain_type="COMPLETE"
        ),
        analyze_certificate_record(
            cert_id="CERT-004",
            session_id="SMTP-0001",
            subject_cn="mx.sentinel-security.org",
            issuer_cn="DigiCert Global TLS RSA4096 Root CA",
            serial_number="77:AA:BB:CC:DD:EE:11:22:33",
            fingerprint_sha256="88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77",
            valid_from_str="2026-01-01T00:00:00Z",
            valid_until_str="2027-01-01T23:59:59Z",
            public_key_alg="RSA",
            key_length=4096,
            sig_alg="sha256WithRSAEncryption",
            san_list=["mx.sentinel-security.org", "mail.sentinel-security.org", "smtp.sentinel-security.org"],
            is_self_signed=False,
            chain_type="COMPLETE"
        ),
        analyze_certificate_record(
            cert_id="CERT-005",
            session_id="POP3-0004",
            subject_cn="pop3.legacy-branch.com",
            issuer_cn="Sectigo RSA Domain Validation Secure Server CA",
            serial_number="99:88:77:66:55:44:33:22:11",
            fingerprint_sha256="44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33",
            valid_from_str="2025-05-10T00:00:00Z",
            valid_until_str="2026-11-20T23:59:59Z",
            public_key_alg="RSA",
            key_length=2048,
            sig_alg="sha256WithRSAEncryption",
            san_list=["pop3.legacy-branch.com"],
            is_self_signed=False,
            chain_type="INCOMPLETE"
        )
    ]
    
    # 2. Build Core Exemplar Sessions with detailed communication ladder flows
    sessions: List[EmailSession] = []
    tls_handshakes: List[TLSHandshake] = []

    def make_comm_flow(proto: str, is_starttls: bool, tls_ver: str, status: str) -> List[CommunicationStep]:
        steps = []
        t = 0.0
        steps.append(CommunicationStep(
            step_number=1, sender="Client", protocol_layer="TCP",
            command_or_status="SYN (Port 25/587/143)", is_encrypted=False,
            timestamp_offset_ms=round(t, 2), description="Initial TCP 3-Way Handshake SYN segment",
            raw_payload_snippet="[TCP SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256"
        ))
        t += 14.2
        steps.append(CommunicationStep(
            step_number=2, sender="Server", protocol_layer="TCP",
            command_or_status="SYN-ACK", is_encrypted=False,
            timestamp_offset_ms=round(t, 2), description="TCP Handshake SYN-ACK acknowledgment",
            raw_payload_snippet="[TCP SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0"
        ))
        t += 1.1
        steps.append(CommunicationStep(
            step_number=3, sender="Client", protocol_layer="TCP",
            command_or_status="ACK", is_encrypted=False,
            timestamp_offset_ms=round(t, 2), description="TCP Handshake established (3-Way Completed)",
            raw_payload_snippet="[TCP ACK] Seq=1 Ack=1 Win=64240 Len=0"
        ))
        t += 8.5
        
        if proto == "SMTP":
            steps.append(CommunicationStep(
                step_number=4, sender="Server", protocol_layer="SMTP",
                command_or_status="220 mail.corp.net ESMTP Postfix Service Ready", is_encrypted=False,
                timestamp_offset_ms=round(t, 2), description="Server Banner advertisement",
                raw_payload_snippet="220 mail.corp.net ESMTP Postfix (Ubuntu)\\r\\n"
            ))
            t += 12.0
            steps.append(CommunicationStep(
                step_number=5, sender="Client", protocol_layer="SMTP",
                command_or_status="EHLO gateway.client-net.org", is_encrypted=False,
                timestamp_offset_ms=round(t, 2), description="Client Extended HELO greeting",
                raw_payload_snippet="EHLO gateway.client-net.org\\r\\n"
            ))
            t += 9.4
            steps.append(CommunicationStep(
                step_number=6, sender="Server", protocol_layer="SMTP",
                command_or_status="250-STARTTLS (8BITMIME / SIZE 35882000)", is_encrypted=False,
                timestamp_offset_ms=round(t, 2), description="Server announces STARTTLS extension capability",
                raw_payload_snippet="250-mail.corp.net\\r\\n250-PIPELINING\\r\\n250-SIZE 35882000\\r\\n250-STARTTLS\\r\\n250 ENHANCEDSTATUSCODES\\r\\n"
            ))
            t += 11.2
            
            if is_starttls and status != "DOWNGRADED":
                steps.append(CommunicationStep(
                    step_number=7, sender="Client", protocol_layer="SMTP",
                    command_or_status="STARTTLS", is_encrypted=False,
                    timestamp_offset_ms=round(t, 2), description="Client requests cryptographic upgrade to TLS",
                    raw_payload_snippet="STARTTLS\\r\\n"
                ))
                t += 8.7
                steps.append(CommunicationStep(
                    step_number=8, sender="Server", protocol_layer="SMTP",
                    command_or_status="220 2.0.0 Ready to start TLS", is_encrypted=False,
                    timestamp_offset_ms=round(t, 2), description="Server acknowledges TLS readiness; socket switches to TLS record layer",
                    raw_payload_snippet="220 2.0.0 Ready to start TLS\\r\\n"
                ))
                t += 14.5
                steps.append(CommunicationStep(
                    step_number=9, sender="Client", protocol_layer="TLS",
                    command_or_status=f"ClientHello ({tls_ver}, SNI=mail.corp.net)", is_encrypted=False,
                    timestamp_offset_ms=round(t, 2), description="TLS ClientHello advertising cipher suites & supported extensions",
                    raw_payload_snippet=f"TLS Record Layer: Handshake Protocol: Client Hello (Version: {tls_ver})"
                ))
                t += 16.3
                steps.append(CommunicationStep(
                    step_number=10, sender="Server", protocol_layer="TLS",
                    command_or_status="ServerHello + Certificate + ServerKeyExchange + ServerHelloDone", is_encrypted=False,
                    timestamp_offset_ms=round(t, 2), description="Server selects cipher suite and transmits X.509 certificate chain",
                    raw_payload_snippet="TLS Record Layer: Handshake Protocol: Server Hello, Certificate, Server Key Exchange"
                ))
                t += 22.0
                steps.append(CommunicationStep(
                    step_number=11, sender="Client", protocol_layer="TLS",
                    command_or_status="ClientKeyExchange + ChangeCipherSpec + Finished", is_encrypted=True,
                    timestamp_offset_ms=round(t, 2), description="Key exchange negotiated; transition to encrypted record stream",
                    raw_payload_snippet="TLS Record Layer: Handshake Protocol: Encrypted Handshake Message"
                ))
                t += 15.0
                steps.append(CommunicationStep(
                    step_number=12, sender="Client", protocol_layer="SMTP (Encrypted)",
                    command_or_status="[TLS Application Data: MAIL FROM / RCPT TO / DATA payload]", is_encrypted=True,
                    timestamp_offset_ms=round(t, 2), description="Encrypted email transaction payload transmission",
                    raw_payload_snippet="[Encrypted Application Data: 4,096 bytes AES-GCM]"
                ))
            elif status == "DOWNGRADED":
                steps.append(CommunicationStep(
                    step_number=7, sender="Client", protocol_layer="SMTP",
                    command_or_status="STARTTLS", is_encrypted=False,
                    timestamp_offset_ms=round(t, 2), description="Client requests STARTTLS upgrade",
                    raw_payload_snippet="STARTTLS\\r\\n"
                ))
                t += 15.2
                steps.append(CommunicationStep(
                    step_number=8, sender="Server", protocol_layer="SMTP",
                    command_or_status="454 4.7.0 TLS not available due to temporary reason", is_encrypted=False,
                    timestamp_offset_ms=round(t, 2), description="Server rejects TLS upgrade (STARTTLS Downgrade / Stripping)",
                    raw_payload_snippet="454 4.7.0 TLS not available due to temporary reason\\r\\n"
                ))
                t += 10.1
                steps.append(CommunicationStep(
                    step_number=9, sender="Client", protocol_layer="SMTP",
                    command_or_status="MAIL FROM:<ceo@enterprise-corp.com> (Insecure Fallback)", is_encrypted=False,
                    timestamp_offset_ms=round(t, 2), description="Client fell back to unencrypted transmission!",
                    raw_payload_snippet="MAIL FROM:<ceo@enterprise-corp.com>\\r\\n"
                ))
        elif proto == "IMAP":
            steps.append(CommunicationStep(
                step_number=4, sender="Server", protocol_layer="IMAP",
                command_or_status="* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN] Dovecot ready.", is_encrypted=False,
                timestamp_offset_ms=round(t, 2), description="IMAP Greeting banner with STARTTLS capability",
                raw_payload_snippet="* OK [CAPABILITY IMAP4rev1 STARTTLS] IMAP4rev1 Server\\r\\n"
            ))
            t += 12.0
            if is_starttls:
                steps.append(CommunicationStep(
                    step_number=5, sender="Client", protocol_layer="IMAP",
                    command_or_status=". STARTTLS", is_encrypted=False,
                    timestamp_offset_ms=round(t, 2), description="IMAP Client initiates STARTTLS command",
                    raw_payload_snippet=". STARTTLS\\r\\n"
                ))
                t += 9.5
                steps.append(CommunicationStep(
                    step_number=6, sender="Server", protocol_layer="IMAP",
                    command_or_status=". OK Begin TLS negotiation now", is_encrypted=False,
                    timestamp_offset_ms=round(t, 2), description="IMAP server signals TLS readiness",
                    raw_payload_snippet=". OK Begin TLS negotiation now\\r\\n"
                ))
                t += 18.0
                steps.append(CommunicationStep(
                    step_number=7, sender="Client", protocol_layer="TLS",
                    command_or_status=f"ClientHello ({tls_ver})", is_encrypted=False,
                    timestamp_offset_ms=round(t, 2), description="TLS ClientHello over IMAP stream",
                    raw_payload_snippet=f"TLS Handshake Client Hello ({tls_ver})"
                ))
                t += 20.0
                steps.append(CommunicationStep(
                    step_number=8, sender="Server", protocol_layer="TLS",
                    command_or_status="ServerHello + Certificate + Handshake Done", is_encrypted=False,
                    timestamp_offset_ms=round(t, 2), description="TLS Handshake negotiated successfully",
                    raw_payload_snippet="TLS Handshake Server Hello, Certificate"
                ))
                t += 15.0
                steps.append(CommunicationStep(
                    step_number=9, sender="Client", protocol_layer="IMAP (Encrypted)",
                    command_or_status="[TLS Application Data: Authenticated Fetch / Sync]", is_encrypted=True,
                    timestamp_offset_ms=round(t, 2), description="Encrypted IMAP mailbox synchronization",
                    raw_payload_snippet="[Encrypted Application Data]"
                ))
            else:
                steps.append(CommunicationStep(
                    step_number=5, sender="Client", protocol_layer="IMAP",
                    command_or_status="A001 LOGIN user@corp.net P@ssw0rd123! (Cleartext Exposure)", is_encrypted=False,
                    timestamp_offset_ms=round(t, 2), description="Plaintext IMAP credentials transmitted without encryption!",
                    raw_payload_snippet="A001 LOGIN user@corp.net P@ssw0rd123!\\r\\n"
                ))
        else: # POP3
            steps.append(CommunicationStep(
                step_number=4, sender="Server", protocol_layer="POP3",
                command_or_status="+OK POP3 server ready <1892.671@mail.corp.com>", is_encrypted=False,
                timestamp_offset_ms=round(t, 2), description="POP3 Server Greeting",
                raw_payload_snippet="+OK POP3 server ready\\r\\n"
            ))
            t += 14.0
            if is_starttls:
                steps.append(CommunicationStep(
                    step_number=5, sender="Client", protocol_layer="POP3",
                    command_or_status="STLS", is_encrypted=False,
                    timestamp_offset_ms=round(t, 2), description="POP3 STLS command",
                    raw_payload_snippet="STLS\\r\\n"
                ))
                t += 10.0
                steps.append(CommunicationStep(
                    step_number=6, sender="Server", protocol_layer="POP3",
                    command_or_status="+OK Begin TLS negotiation", is_encrypted=False,
                    timestamp_offset_ms=round(t, 2), description="Server switches to TLS",
                    raw_payload_snippet="+OK Begin TLS negotiation\\r\\n"
                ))
                t += 20.0
                steps.append(CommunicationStep(
                    step_number=7, sender="Client", protocol_layer="TLS",
                    command_or_status=f"TLS Handshake ({tls_ver})", is_encrypted=False,
                    timestamp_offset_ms=round(t, 2), description="POP3 TLS Handshake completed",
                    raw_payload_snippet=f"TLS Handshake Protocol ({tls_ver})"
                ))
                t += 15.0
                steps.append(CommunicationStep(
                    step_number=8, sender="Client", protocol_layer="POP3 (Encrypted)",
                    command_or_status="[TLS Application Data: POP3 RETR]", is_encrypted=True,
                    timestamp_offset_ms=round(t, 2), description="Encrypted POP3 message retrieval",
                    raw_payload_snippet="[Encrypted Application Data]"
                ))
            else:
                steps.append(CommunicationStep(
                    step_number=5, sender="Client", protocol_layer="POP3",
                    command_or_status="USER sales@corp.net / PASS SecretPass99", is_encrypted=False,
                    timestamp_offset_ms=round(t, 2), description="Plaintext POP3 user authentication",
                    raw_payload_snippet="USER sales@corp.net\\r\\nPASS SecretPass99\\r\\n"
                ))
        return steps

    # Defined archetype sessions to represent the full forensic breadth
    archetypes = [
        {
            "id": "SMTP-0042", "proto": "SMTP", "src_ip": "192.168.10.45", "src_port": 49182,
            "dst_ip": "10.0.5.25", "dst_port": 25, "client_host": "mail.enterprise-corp.com",
            "banner": "220 mail.enterprise-corp.com ESMTP Postfix", "starttls": True,
            "tls_ver": "TLS 1.0", "cipher": "DES-CBC3-SHA", "cert_id": "CERT-001",
            "risk": "CRITICAL", "status": "ENCRYPTED", "duration": 4820, "pkts": 612, "bytes": 482910,
            "flags": ["Deprecated TLS 1.0", "Weak 3DES Cipher", "Expired X.509 Cert", "No Forward Secrecy"],
            "risk_factors": ["+25 TLS 1.0 Deprecation", "+20 3DES Sweet32", "+20 Expired Certificate", "+10 Static RSA No PFS"],
            "risk_score": 94
        },
        {
            "id": "SMTP-0015", "proto": "SMTP", "src_ip": "192.168.10.88", "src_port": 51230,
            "dst_ip": "10.0.5.30", "dst_port": 587, "client_host": "internal-relay.corp.local",
            "banner": "220 internal-relay.corp.local ESMTP Exim 4.94", "starttls": True,
            "tls_ver": "TLS 1.1", "cipher": "RC4-SHA", "cert_id": "CERT-002",
            "risk": "CRITICAL", "status": "ENCRYPTED", "duration": 3100, "pkts": 418, "bytes": 312050,
            "flags": ["Deprecated TLS 1.1", "Broken RC4 Stream Cipher", "Self-Signed Certificate", "Weak 1024-bit RSA Key", "SHA-1 Signature"],
            "risk_factors": ["+25 TLS 1.1 Deprecation", "+20 Insecure RC4", "+15 Self-Signed Cert", "+12 Weak 1024-bit Key", "+10 SHA-1 Hash"],
            "risk_score": 96
        },
        {
            "id": "IMAP-0008", "proto": "IMAP", "src_ip": "172.16.20.12", "src_port": 54890,
            "dst_ip": "10.0.5.143", "dst_port": 143, "client_host": "imap.cloudmail-gateway.net",
            "banner": "* OK Dovecot IMAP ready", "starttls": True,
            "tls_ver": "TLS 1.2", "cipher": "ECDHE-RSA-AES256-GCM-SHA384", "cert_id": "CERT-003",
            "risk": "MEDIUM", "status": "ENCRYPTED", "duration": 1850, "pkts": 310, "bytes": 184500,
            "flags": ["Certificate Expiring in 12 Days", "Modern TLS 1.2 AEAD"],
            "risk_factors": ["+15 Certificate Expiring Soon (12 days)", "+0 Modern ECDHE-GCM"],
            "risk_score": 42
        },
        {
            "id": "SMTP-0001", "proto": "SMTP", "src_ip": "192.168.1.100", "src_port": 44102,
            "dst_ip": "10.0.5.25", "dst_port": 25, "client_host": "mx.sentinel-security.org",
            "banner": "220 mx.sentinel-security.org ESMTP Postfix Ready", "starttls": True,
            "tls_ver": "TLS 1.3", "cipher": "TLS_AES_256_GCM_SHA384", "cert_id": "CERT-004",
            "risk": "LOW", "status": "ENCRYPTED", "duration": 820, "pkts": 240, "bytes": 98400,
            "flags": ["TLS 1.3 Best Practice", "Forward Secrecy Verified", "Modern AEAD", "Valid Certificate"],
            "risk_factors": ["+0 Optimal Cryptographic Posture"],
            "risk_score": 8
        },
        {
            "id": "SMTP-0077", "proto": "SMTP", "src_ip": "192.168.10.99", "src_port": 50110,
            "dst_ip": "10.0.5.25", "dst_port": 25, "client_host": "outbound-relay.vendor.com",
            "banner": "220 mail.corp.net ESMTP", "starttls": True,
            "tls_ver": "None", "cipher": "None", "cert_id": None,
            "risk": "CRITICAL", "status": "DOWNGRADED", "duration": 2200, "pkts": 190, "bytes": 67000,
            "flags": ["STARTTLS Stripping Downgrade", "Cleartext Transmission"],
            "risk_factors": ["+25 STARTTLS Downgrade Error 454", "+20 Cleartext Fallback"],
            "risk_score": 92
        },
        {
            "id": "POP3-0004", "proto": "POP3", "src_ip": "172.16.30.5", "src_port": 48210,
            "dst_ip": "10.0.5.110", "dst_port": 110, "client_host": "pop3.legacy-branch.com",
            "banner": "+OK POP3 Server Ready", "starttls": True,
            "tls_ver": "TLS 1.2", "cipher": "AES128-SHA256", "cert_id": "CERT-005",
            "risk": "HIGH", "status": "ENCRYPTED", "duration": 1450, "pkts": 210, "bytes": 112000,
            "flags": ["Missing Forward Secrecy (Static RSA)", "Incomplete Intermediate Cert Chain", "CBC Mode Cipher"],
            "risk_factors": ["+15 No PFS (Static RSA)", "+12 Incomplete Chain", "+10 CBC Cipher Suite"],
            "risk_score": 68
        },
        {
            "id": "IMAP-0021", "proto": "IMAP", "src_ip": "192.168.20.15", "src_port": 52900,
            "dst_ip": "10.0.5.143", "dst_port": 143, "client_host": "imap.internal.local",
            "banner": "* OK IMAP4rev1 Ready", "starttls": False,
            "tls_ver": "None", "cipher": "None", "cert_id": None,
            "risk": "HIGH", "status": "PLAINTEXT", "duration": 940, "pkts": 120, "bytes": 45000,
            "flags": ["No Encryption (Plaintext IMAP)", "Credentials Exposed"],
            "risk_factors": ["+20 Missing STARTTLS", "+15 Cleartext Auth Commands"],
            "risk_score": 75
        }
    ]

    # Generate 127 total sessions matching exact distribution (SMTP: 61, IMAP: 44, POP3: 22)
    # Total TLS sessions = 109, STARTTLS = 103
    smtp_count = 0
    imap_count = 0
    pop3_count = 0
    
    for i in range(1, 128):
        offset = timedelta(seconds=i * 18)
        start_str = (base_time + offset).strftime("%Y-%m-%d %H:%M:%S UTC")
        end_str = (base_time + offset + timedelta(seconds=2)).strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Pick protocol to match exact distribution: 61 SMTP, 44 IMAP, 22 POP3
        if smtp_count < 61:
            proto = "SMTP"
            smtp_count += 1
            dst_port = 25 if smtp_count % 3 != 0 else 587
        elif imap_count < 44:
            proto = "IMAP"
            imap_count += 1
            dst_port = 143 if imap_count % 4 != 0 else 993
        else:
            proto = "POP3"
            pop3_count += 1
            dst_port = 110 if pop3_count % 3 != 0 else 995

        # Pick matching archetype for rich detail or procedural secure/medium sessions
        if i <= len(archetypes):
            arch = archetypes[i - 1]
            s_id = arch["id"]
            proto = arch["proto"]
            dst_port = arch["dst_port"]
            src_ip = arch["src_ip"]
            dst_ip = arch["dst_ip"]
            src_port = arch["src_port"]
            client_host = arch["client_host"]
            banner = arch["banner"]
            starttls_req = arch["starttls"]
            starttls_succ = arch["status"] == "ENCRYPTED"
            tls_v = arch["tls_ver"]
            c_suite = arch["cipher"]
            c_id = arch["cert_id"]
            risk_level = arch["risk"]
            s_status = arch["status"]
            dur = arch["duration"]
            pkts = arch["pkts"]
            bytes_c = arch["bytes"]
            flags = arch["flags"]
            risk_factors = arch["risk_factors"]
            r_score = arch["risk_score"]
            comm_flow = make_comm_flow(proto, starttls_req, tls_v, s_status)
        else:
            # Procedurally generate secure & typical corporate email sessions
            s_id = f"{proto}-{i:04d}"
            src_ip = f"192.168.10.{(i % 150) + 10}"
            src_port = 45000 + i
            dst_ip = f"10.0.5.{25 if proto == 'SMTP' else (143 if proto == 'IMAP' else 110)}"
            client_host = f"client-{i}.corp.net"
            banner = f"220 {proto.lower()}.corp.net ESMTP Service" if proto == 'SMTP' else f"* OK {proto} Service"
            
            # Distribution: 109 TLS sessions, 103 STARTTLS, 18 unencrypted/downgraded
            if i <= 109:
                starttls_req = True
                starttls_succ = True
                s_status = "ENCRYPTED"
                if i % 5 == 0:
                    tls_v = "TLS 1.2"
                    c_suite = "ECDHE-RSA-AES128-GCM-SHA256"
                    c_id = "CERT-004"
                    risk_level = "LOW"
                    r_score = 15
                    flags = ["TLS 1.2 Standard", "AEAD Active", "PFS Verified"]
                    risk_factors = ["+0 Baseline Secure TLS 1.2"]
                elif i % 7 == 0:
                    tls_v = "TLS 1.2"
                    c_suite = "AES256-GCM-SHA384" # Static RSA
                    c_id = "CERT-004"
                    risk_level = "MEDIUM"
                    r_score = 38
                    flags = ["Static RSA Key Exchange", "No Forward Secrecy"]
                    risk_factors = ["+10 Static RSA Key Exchange (Missing PFS)"]
                else:
                    tls_v = "TLS 1.3"
                    c_suite = "TLS_AES_256_GCM_SHA384"
                    c_id = "CERT-004"
                    risk_level = "LOW"
                    r_score = 5
                    flags = ["TLS 1.3 Modern Standard", "Perfect Forward Secrecy", "Valid X.509 Chain"]
                    risk_factors = ["+0 High Assurance Security"]
            else:
                starttls_req = False
                starttls_succ = False
                s_status = "PLAINTEXT"
                tls_v = None
                c_suite = None
                c_id = None
                risk_level = "HIGH" if proto in ["IMAP", "POP3"] else "MEDIUM"
                r_score = 70 if proto in ["IMAP", "POP3"] else 50
                flags = ["Plaintext Email Session", "Missing STARTTLS Encryption"]
                risk_factors = ["+15 Plaintext Transmission over Port " + str(dst_port)]

            dur = 650 + (i * 15) % 2200
            pkts = 180 + (i * 7) % 350
            bytes_c = pkts * 840
            comm_flow = make_comm_flow(proto, starttls_req, tls_v or "TLS 1.3", s_status)

        session_obj = EmailSession(
            session_id=s_id,
            protocol=proto,
            source_ip=src_ip,
            source_port=src_port,
            dest_ip=dst_ip,
            dest_port=dst_port,
            client_hostname=client_host,
            server_banner=banner,
            starttls_requested=starttls_req,
            starttls_success=starttls_succ,
            tls_version=tls_v,
            cipher_suite=c_suite,
            certificate_subject="mail.enterprise-corp.com" if c_id else None,
            certificate_id=c_id,
            risk=risk_level,
            status=s_status,
            start_time=start_str,
            end_time=end_str,
            duration_ms=dur,
            packet_count=pkts,
            byte_count=bytes_c,
            communication_flow=comm_flow,
            flags=flags,
            explainable_risk_factors=risk_factors,
            risk_score=r_score
        )
        sessions.append(session_obj)

        # Build TLSHandshake object if TLS is present
        if tls_v and tls_v != "None":
            tls_handshakes.append(analyze_tls_session(
                session_id=s_id,
                tls_version=tls_v,
                cipher_suite=c_suite,
                sni=client_host,
                alpn=proto.lower()
            ))

    # 3. Generate Findings, Anomalies, and AI Risk
    findings = generate_cryptographic_findings(sessions, tls_handshakes, certificates)
    anomalies = detect_anomalies(sessions, tls_handshakes, certificates)
    risk_assessment, threat_matrix, security_posture = evaluate_risk_assessment(sessions, findings, anomalies)

    # 4. Generate Timeline of suspicious events
    timeline_events: List[TimelineEvent] = [
        TimelineEvent(
            id="EVT-01",
            timestamp="2026-09-28 14:30:18 UTC",
            session_id="SMTP-0042",
            protocol="SMTP",
            event_type="CRYPTOGRAPHIC_DEPRECATION",
            severity="critical",
            title="Deprecated TLS 1.0 & 3DES Suite Handshake Negotiated",
            description="Client 192.168.10.45 negotiated TLS 1.0 with 3DES-CBC3-SHA cipher suite and expired X.509 certificate.",
            source_ip="192.168.10.45",
            dest_ip="10.0.5.25",
            details={"cipher": "DES-CBC3-SHA", "tls": "TLS 1.0", "cert": "Expired"}
        ),
        TimelineEvent(
            id="EVT-02",
            timestamp="2026-09-28 14:31:45 UTC",
            session_id="SMTP-0015",
            protocol="SMTP",
            event_type="WEAK_CIPHER_AND_KEY",
            severity="critical",
            title="Prohibited RC4 Stream Cipher & 1024-bit RSA Key Observed",
            description="Client 192.168.10.88 negotiated RC4-SHA with a self-signed 1024-bit RSA certificate on submission port 587.",
            source_ip="192.168.10.88",
            dest_ip="10.0.5.30",
            details={"cipher": "RC4-SHA", "key_len": 1024, "sig": "sha1WithRSAEncryption"}
        ),
        TimelineEvent(
            id="EVT-03",
            timestamp="2026-09-28 14:33:10 UTC",
            session_id="SMTP-0077",
            protocol="SMTP",
            event_type="STARTTLS_DOWNGRADE",
            severity="critical",
            title="STARTTLS Stripping / Downgrade Failure",
            description="Mail client attempted STARTTLS upgrade, server returned 454 error code; traffic reverted to unencrypted cleartext.",
            source_ip="192.168.10.99",
            dest_ip="10.0.5.25",
            details={"action": "Plaintext Fallback", "status_code": 454}
        ),
        TimelineEvent(
            id="EVT-04",
            timestamp="2026-09-28 14:34:22 UTC",
            session_id="IMAP-0021",
            protocol="IMAP",
            event_type="CLEARTEXT_AUTH_LEAK",
            severity="high",
            title="Plaintext IMAP User Authentication Credentials Exposed",
            description="User authentication command sent over unencrypted TCP session without prior STARTTLS activation.",
            source_ip="192.168.20.15",
            dest_ip="10.0.5.143",
            details={"command": "A001 LOGIN", "encrypted": False}
        ),
        TimelineEvent(
            id="EVT-05",
            timestamp="2026-09-28 14:36:05 UTC",
            session_id="POP3-0004",
            protocol="POP3",
            event_type="PFS_MISSING",
            severity="medium",
            title="Static RSA Key Exchange (Missing Forward Secrecy)",
            description="POP3 session negotiated AES128-SHA256 with static RSA key exchange and incomplete certificate chain.",
            source_ip="172.16.30.5",
            dest_ip="10.0.5.110",
            details={"pfs": False, "chain": "INCOMPLETE"}
        ),
        TimelineEvent(
            id="EVT-06",
            timestamp="2026-09-28 14:38:50 UTC",
            session_id="IMAP-0008",
            protocol="IMAP",
            event_type="CERT_EXPIRING",
            severity="medium",
            title="Certificate Expiring in 12 Days Warning",
            description="Server presented X.509 certificate for imap.cloudmail-gateway.net nearing expiration threshold.",
            source_ip="172.16.20.12",
            dest_ip="10.0.5.143",
            details={"days_remaining": 12, "issuer": "Let's Encrypt"}
        )
    ]

    # Calculate exact counts
    crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    med_count = sum(1 for f in findings if f.severity == "MEDIUM")
    low_count = sum(1 for f in findings if f.severity == "LOW")

    # Distributions
    proto_dist = ProtocolDistribution(smtp=61, imap=44, pop3=22)
    tls_dist = TLSVersionDistribution(
        tls13=sum(1 for t in tls_handshakes if t.tls_version == "TLS 1.3"),
        tls12=sum(1 for t in tls_handshakes if t.tls_version == "TLS 1.2"),
        tls11=sum(1 for t in tls_handshakes if t.tls_version == "TLS 1.1"),
        tls10=sum(1 for t in tls_handshakes if t.tls_version == "TLS 1.0"),
        ssl_unknown=18 # Unencrypted / plaintext
    )
    risk_dist = RiskDistribution(
        critical=sum(1 for s in sessions if s.risk == "CRITICAL"),
        high=sum(1 for s in sessions if s.risk == "HIGH"),
        medium=sum(1 for s in sessions if s.risk == "MEDIUM"),
        low=sum(1 for s in sessions if s.risk == "LOW"),
        info=0
    )
    crypto_stats = CryptoWeaknessStats(
        deprecated_tls=sum(1 for t in tls_handshakes if t.tls_version in ["TLS 1.0", "TLS 1.1"]),
        weak_cipher=sum(1 for t in tls_handshakes if "3DES" in t.cipher_suite or "RC4" in t.cipher_suite),
        cert_expired=sum(1 for c in certificates if c.is_expired),
        cert_misconfig=sum(1 for c in certificates if c.chain_status != "COMPLETE" or c.is_self_signed),
        missing_pfs=sum(1 for t in tls_handshakes if not t.forward_secrecy),
        weak_key=sum(1 for c in certificates if c.key_length < 2048),
        insecure_sig_alg=sum(1 for c in certificates if "SHA1" in c.signature_algorithm or "MD5" in c.signature_algorithm),
        insecure_starttls=sum(1 for s in sessions if s.status in ["DOWNGRADED", "PLAINTEXT"])
    )

    return PCAPAnalysis(
        id="ANALYSIS-DEMO-001",
        filename="enterprise_mail_capture.pcap",
        file_size_bytes=48392000,
        file_size_formatted="46.15 MB",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        upload_timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        analysis_duration_seconds=3.42,
        is_demo=True,
        status="COMPLETED",
        total_packets=48392,
        total_email_sessions=127,
        total_tls_sessions=109,
        total_starttls_sessions=103,
        total_certificates=len(certificates),
        critical_findings_count=3,
        high_findings_count=12,
        medium_findings_count=18,
        low_findings_count=low_count,
        security_score=71,
        protocol_distribution=proto_dist,
        tls_version_distribution=tls_dist,
        risk_distribution=risk_dist,
        crypto_weakness_stats=crypto_stats,
        sessions=sessions,
        tls_handshakes=tls_handshakes,
        certificates=certificates,
        findings=findings,
        anomalies=anomalies,
        timeline=timeline_events,
        risk_assessment=risk_assessment,
        threat_matrix=threat_matrix,
        security_posture=security_posture
    )
