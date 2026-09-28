"""
Cryptographic Weakness Engine for MailFlow Sentinel
Identifies policy violations, deprecations, weak keys/ciphers, and STARTTLS security flaws.
"""
from typing import List
from backend.models.schemas import Finding, EmailSession, TLSHandshake, Certificate

def generate_cryptographic_findings(
    sessions: List[EmailSession],
    tls_handshakes: List[TLSHandshake],
    certificates: List[Certificate]
) -> List[Finding]:
    """Generate standardized forensic findings from reconstructed sessions and cryptographic metadata."""
    findings: List[Finding] = []
    finding_id_counter = 1
    
    tls_map = {t.session_id: t for t in tls_handshakes}
    cert_map = {c.session_id: c for c in certificates}
    
    for session in sessions:
        tls = tls_map.get(session.session_id)
        cert = cert_map.get(session.session_id)
        
        # 1. Plaintext / Missing STARTTLS
        if not session.starttls_requested and session.status == "PLAINTEXT":
            findings.append(Finding(
                id=f"CRYPTO-{finding_id_counter:03d}",
                title="Insecure Plaintext Email Session (Missing STARTTLS)",
                severity="HIGH",
                category="STARTTLS",
                session_id=session.session_id,
                protocol=session.protocol,
                evidence_observed=f"{session.protocol} stream negotiated without STARTTLS encryption",
                expected_secure="Mandatory STARTTLS / Implicit TLS (Port 465/993/995)",
                evidence_detail=f"Traffic on port {session.dest_port} transmitted in cleartext. Credentials and message headers exposed to passive network wiretapping.",
                packet_stream_ref=f"TCP Stream {session.session_id} (Packets 1-{session.packet_count})",
                impact="Eavesdropping on email communications, sensitive attachments, and potential credential theft.",
                recommendation="Enforce mandatory STARTTLS with strict rejection of unencrypted connections, or migrate to implicit TLS ports.",
                cwe_id="CWE-319",
                cvss_score=7.4
            ))
            finding_id_counter += 1

        # 2. STARTTLS Plaintext Downgrade
        if session.status == "DOWNGRADED":
            findings.append(Finding(
                id=f"CRYPTO-{finding_id_counter:03d}",
                title="Insecure STARTTLS Stripping / Downgrade Detected",
                severity="CRITICAL",
                category="STARTTLS",
                session_id=session.session_id,
                protocol=session.protocol,
                evidence_observed="Server capability 250-STARTTLS stripped or responded with 454/500 error, falling back to cleartext",
                expected_secure="Require TLS (RFC 8461 MTA-STS / DANE TLSA enforcement)",
                evidence_detail=f"The client attempted STARTTLS negotiation, but traffic fell back to unencrypted transmission.",
                packet_stream_ref=f"TCP Stream {session.session_id} (Handshake transition sequence)",
                impact="Active adversary stripping protection or severe configuration flaw exposing email transit in plaintext.",
                recommendation="Configure strict MTA-STS (Mail Transfer Agent Strict Transport Security) or DANE TLSA to prevent opportunistic downgrade attacks.",
                cwe_id="CWE-757",
                cvss_score=8.9
            ))
            finding_id_counter += 1

        # 3. TLS Version Checks
        if tls:
            if tls.tls_version in ["TLS 1.0", "TLS 1.1", "SSL 3.0"]:
                findings.append(Finding(
                    id=f"CRYPTO-{finding_id_counter:03d}",
                    title="Deprecated TLS Version Protocol In Use",
                    severity="HIGH" if tls.tls_version != "SSL 3.0" else "CRITICAL",
                    category="TLS Configuration",
                    session_id=session.session_id,
                    protocol=session.protocol,
                    evidence_observed=f"Observed: {tls.tls_version}",
                    expected_secure="TLS 1.2 or TLS 1.3 (RFC 8996 compliance)",
                    evidence_detail=f"Client and Server negotiated {tls.tls_version}. This protocol version lacks modern cryptographic protections and is formally deprecated by IETF.",
                    packet_stream_ref=f"ServerHello Record (Session {session.session_id})",
                    impact="Susceptibility to cryptographic downgrade attacks, BEAST (CVE-2011-3389), and POODLE vulnerabilities.",
                    recommendation="Disable TLS 1.0, TLS 1.1, and SSL 3.0 on mail server daemons (Postfix, Exim, Dovecot, Exchange). Enforce minimum TLS 1.2.",
                    cwe_id="CWE-326",
                    cvss_score=7.5
                ))
                finding_id_counter += 1

            # 4. Cipher Suite Weakness
            if "3DES" in tls.cipher_suite or "DES" in tls.cipher_suite:
                findings.append(Finding(
                    id=f"CRYPTO-{finding_id_counter:03d}",
                    title="Weak 64-bit Block Cipher Suite (3DES Sweet32)",
                    severity="HIGH",
                    category="Cipher Suite",
                    session_id=session.session_id,
                    protocol=session.protocol,
                    evidence_observed=f"Cipher Suite: {tls.cipher_suite}",
                    expected_secure="AES-GCM (128/256) or ChaCha20-Poly1305 AEAD suites",
                    evidence_detail="3DES uses a 64-bit block size. Birthday attacks allow plaintext recovery after capturing roughly 32GB of data over the same TLS session.",
                    packet_stream_ref=f"CipherSuite Negotiation (Session {session.session_id})",
                    impact="Passive adversary with high packet capture volume can decrypt portions of HTTP/SMTP session tokens.",
                    recommendation="Remove 3DES and all DES-based ciphers from the server cipher suite list.",
                    cwe_id="CWE-327",
                    cvss_score=7.1
                ))
                finding_id_counter += 1

            if "RC4" in tls.cipher_suite:
                findings.append(Finding(
                    id=f"CRYPTO-{finding_id_counter:03d}",
                    title="Prohibited RC4 Stream Cipher In Use",
                    severity="CRITICAL",
                    category="Cipher Suite",
                    session_id=session.session_id,
                    protocol=session.protocol,
                    evidence_observed=f"Cipher Suite: {tls.cipher_suite}",
                    expected_secure="Modern AEAD Ciphers (AES-256-GCM, AES-128-GCM)",
                    evidence_detail="RC4 has known biometric single-byte biases and keystream vulnerabilities prohibited by RFC 7465.",
                    packet_stream_ref=f"CipherSuite Negotiation (Session {session.session_id})",
                    impact="Full stream decryption possibility via statistical keystream biases.",
                    recommendation="Immediately disable RC4 suites across all mail server configurations.",
                    cwe_id="CWE-327",
                    cvss_score=9.1
                ))
                finding_id_counter += 1

            # 5. Missing Forward Secrecy
            if not tls.forward_secrecy and tls.tls_version != "None":
                findings.append(Finding(
                    id=f"CRYPTO-{finding_id_counter:03d}",
                    title="Missing Perfect Forward Secrecy (Static RSA Key Exchange)",
                    severity="MEDIUM",
                    category="Key Exchange",
                    session_id=session.session_id,
                    protocol=session.protocol,
                    evidence_observed=f"Key Exchange: {tls.key_exchange} (No (EC)DHE)",
                    expected_secure="Ephemeral Diffie-Hellman (ECDHE / DHE) Key Exchange",
                    evidence_detail="Static RSA key exchange does not provide Perfect Forward Secrecy. If the server's private key is compromised in the future, all historically recorded PCAP sessions can be retroactively decrypted.",
                    packet_stream_ref=f"ClientKeyExchange Record (Session {session.session_id})",
                    impact="Loss of retroactive confidentiality for stored PCAP captures if certificates are compromised.",
                    recommendation="Configure mail services to prefer ECDHE key exchange curves (X25519, secp256r1, secp384r1).",
                    cwe_id="CWE-327",
                    cvss_score=5.9
                ))
                finding_id_counter += 1

        # 6. Certificate Weaknesses
        if cert:
            if cert.is_expired:
                findings.append(Finding(
                    id=f"CRYPTO-{finding_id_counter:03d}",
                    title="Expired X.509 Certificate in TLS Handshake",
                    severity="CRITICAL",
                    category="Certificate",
                    session_id=session.session_id,
                    protocol=session.protocol,
                    evidence_observed=f"Valid Until: {cert.valid_until} ({abs(cert.days_remaining)} days overdue)",
                    expected_secure="Active, unexpired certificate with valid automated renewal",
                    evidence_detail=f"Certificate for CN={cert.subject_cn} expired. Connecting MTAs and mail clients will either fail validation or bypass trust checks.",
                    packet_stream_ref=f"Certificate Message (Session {session.session_id})",
                    impact="Connection dropouts, delivery failures, or users habituated into accepting invalid security certificates.",
                    recommendation="Renew the TLS certificate immediately using an ACME automated provider (e.g. Let's Encrypt / Certbot) or enterprise PKI.",
                    cwe_id="CWE-298",
                    cvss_score=8.2
                ))
                finding_id_counter += 1

            if cert.is_self_signed:
                findings.append(Finding(
                    id=f"CRYPTO-{finding_id_counter:03d}",
                    title="Untrusted Self-Signed Certificate Detected",
                    severity="HIGH",
                    category="Certificate",
                    session_id=session.session_id,
                    protocol=session.protocol,
                    evidence_observed=f"Subject CN ({cert.subject_cn}) matches Issuer CN ({cert.issuer_cn})",
                    expected_secure="Publicly trusted Certificate Authority or verified Private Enterprise PKI CA",
                    evidence_detail="Self-signed certificates cannot be verified by remote MTAs and allow undetected passive/active interception.",
                    packet_stream_ref=f"Certificate Chain (Session {session.session_id})",
                    impact="Lack of identity assurance, mail client warning popups, and MITM vulnerability.",
                    recommendation="Replace self-signed certificates with certificates issued by a trusted public CA or properly installed internal trust anchor.",
                    cwe_id="CWE-295",
                    cvss_score=7.4
                ))
                finding_id_counter += 1

            if cert.public_key_algorithm == "RSA" and cert.key_length < 2048:
                findings.append(Finding(
                    id=f"CRYPTO-{finding_id_counter:03d}",
                    title="Weak RSA Public Key Length (1024-bit)",
                    severity="HIGH",
                    category="Key Exchange",
                    session_id=session.session_id,
                    protocol=session.protocol,
                    evidence_observed=f"Key Length: {cert.key_length} bits",
                    expected_secure="RSA >= 2048 bits (or ECDSA >= 256 bits)",
                    evidence_detail="1024-bit RSA keys are vulnerable to factorization with modern cloud compute capabilities.",
                    packet_stream_ref=f"SubjectPublicKeyInfo (Session {session.session_id})",
                    impact="Key factorization leading to private key recovery and session decryption.",
                    recommendation="Re-issue certificate with a minimum 2048-bit RSA key or 256-bit ECDSA key.",
                    cwe_id="CWE-326",
                    cvss_score=7.5
                ))
                finding_id_counter += 1

            if "SHA1" in cert.signature_algorithm.upper() or "MD5" in cert.signature_algorithm.upper():
                findings.append(Finding(
                    id=f"CRYPTO-{finding_id_counter:03d}",
                    title="Weak Certificate Signature Hash Algorithm",
                    severity="HIGH",
                    category="Signature",
                    session_id=session.session_id,
                    protocol=session.protocol,
                    evidence_observed=f"Signature Algorithm: {cert.signature_algorithm}",
                    expected_secure="SHA-256 / SHA-384 with RSA/ECDSA (e.g. ecdsa-with-SHA256)",
                    evidence_detail="Legacy hash functions like SHA-1 and MD5 in X.509 signatures are vulnerable to collision attacks allowing certificate spoofing.",
                    packet_stream_ref=f"Certificate SignatureValue (Session {session.session_id})",
                    impact="Potential certificate forgery and impersonation of enterprise mail domain.",
                    recommendation="Re-issue certificates signed using SHA-256 or SHA-384 hashing algorithms.",
                    cwe_id="CWE-328",
                    cvss_score=7.2
                ))
                finding_id_counter += 1

    return findings
