"""
TLS Forensic Analyzer for MailFlow Sentinel
Inspects TLS Records, Handshake Messages, Cipher Suites, Extensions, and Cryptographic Security.
"""
from typing import Dict, Any, List, Tuple
from backend.models.schemas import TLSHandshake

# Cipher suite database with security classification
CIPHER_SUITE_DB = {
    # TLS 1.3 Suites (Modern, AEAD, PFS mandatory)
    "TLS_AES_256_GCM_SHA384": {
        "kex": "ECDHE", "auth": "AEAD", "enc": "AES-256-GCM", "mac": "SHA384",
        "pfs": True, "strength": "HIGH", "status": "SECURE", "tls_min": "TLS 1.3"
    },
    "TLS_CHACHA20_POLY1305_SHA256": {
        "kex": "ECDHE", "auth": "AEAD", "enc": "ChaCha20-Poly1305", "mac": "SHA256",
        "pfs": True, "strength": "HIGH", "status": "SECURE", "tls_min": "TLS 1.3"
    },
    "TLS_AES_128_GCM_SHA256": {
        "kex": "ECDHE", "auth": "AEAD", "enc": "AES-128-GCM", "mac": "SHA256",
        "pfs": True, "strength": "HIGH", "status": "SECURE", "tls_min": "TLS 1.3"
    },
    # TLS 1.2 Modern Suites
    "ECDHE-RSA-AES256-GCM-SHA384": {
        "kex": "ECDHE", "auth": "RSA", "enc": "AES-256-GCM", "mac": "SHA384",
        "pfs": True, "strength": "HIGH", "status": "SECURE", "tls_min": "TLS 1.2"
    },
    "ECDHE-ECDSA-AES256-GCM-SHA384": {
        "kex": "ECDHE", "auth": "ECDSA", "enc": "AES-256-GCM", "mac": "SHA384",
        "pfs": True, "strength": "HIGH", "status": "SECURE", "tls_min": "TLS 1.2"
    },
    "ECDHE-RSA-AES128-GCM-SHA256": {
        "kex": "ECDHE", "auth": "RSA", "enc": "AES-128-GCM", "mac": "SHA256",
        "pfs": True, "strength": "HIGH", "status": "SECURE", "tls_min": "TLS 1.2"
    },
    "DHE-RSA-AES256-GCM-SHA384": {
        "kex": "DHE", "auth": "RSA", "enc": "AES-256-GCM", "mac": "SHA384",
        "pfs": True, "strength": "HIGH", "status": "SECURE", "tls_min": "TLS 1.2"
    },
    # Legacy / Weak Suites
    "AES256-GCM-SHA384": {
        "kex": "RSA", "auth": "RSA", "enc": "AES-256-GCM", "mac": "SHA384",
        "pfs": False, "strength": "MEDIUM", "status": "NO_PFS", "tls_min": "TLS 1.2"
    },
    "AES128-SHA256": {
        "kex": "RSA", "auth": "RSA", "enc": "AES-128-CBC", "mac": "SHA256",
        "pfs": False, "strength": "MEDIUM", "status": "CBC_NO_PFS", "tls_min": "TLS 1.2"
    },
    "ECDHE-RSA-AES256-SHA": {
        "kex": "ECDHE", "auth": "RSA", "enc": "AES-256-CBC", "mac": "SHA1",
        "pfs": True, "strength": "LOW", "status": "SHA1_CBC", "tls_min": "TLS 1.0"
    },
    "DES-CBC3-SHA": {
        "kex": "RSA", "auth": "RSA", "enc": "3DES-CBC", "mac": "SHA1",
        "pfs": False, "strength": "CRITICAL", "status": "SWEET32_DEPRECATED", "tls_min": "SSL 3.0"
    },
    "RC4-SHA": {
        "kex": "RSA", "auth": "RSA", "enc": "RC4", "mac": "SHA1",
        "pfs": False, "strength": "CRITICAL", "status": "INSECURE_RC4", "tls_min": "SSL 3.0"
    },
    "EXP-RC4-MD5": {
        "kex": "RSA_EXPORT", "auth": "RSA", "enc": "RC4-40", "mac": "MD5",
        "pfs": False, "strength": "CRITICAL", "status": "EXPORT_BROKEN", "tls_min": "SSL 3.0"
    }
}

HEX_TO_CIPHER = {
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0xc030: "ECDHE-RSA-AES256-GCM-SHA384",
    0xc02c: "ECDHE-ECDSA-AES256-GCM-SHA384",
    0xc02f: "ECDHE-RSA-AES128-GCM-SHA256",
    0x009f: "DHE-RSA-AES256-GCM-SHA384",
    0x009d: "AES256-GCM-SHA384",
    0x003c: "AES128-SHA256",
    0xc014: "ECDHE-RSA-AES256-SHA",
    0x000a: "DES-CBC3-SHA",
    0x0005: "RC4-SHA",
    0x0003: "EXP-RC4-MD5"
}

def analyze_tls_session(
    session_id: str,
    tls_version: str,
    cipher_suite: str,
    extensions: List[str] = None,
    alpn: str = None,
    sni: str = None
) -> TLSHandshake:
    """Analyze cryptographic strength and security parameters of a TLS session."""
    if extensions is None:
        extensions = ["server_name", "supported_groups", "ec_point_formats", "signature_algorithms", "application_layer_protocol_negotiation"]
    
    cipher_info = CIPHER_SUITE_DB.get(cipher_suite, {
        "kex": "Unknown", "auth": "Unknown", "enc": "Unknown", "mac": "Unknown",
        "pfs": False, "strength": "UNKNOWN", "status": "UNKNOWN", "tls_min": "TLS 1.2"
    })
    
    warnings = []
    risk = "LOW"
    
    # 1. TLS Version Checks
    if tls_version in ["TLS 1.0", "TLS 1.1", "SSL 3.0", "SSL 2.0"]:
        warnings.append(f"{tls_version} is DEPRECATED and vulnerable to BEAST, POODLE, and downgrade attacks (RFC 8996).")
        risk = "HIGH" if tls_version in ["TLS 1.0", "TLS 1.1"] else "CRITICAL"
    elif tls_version == "TLS 1.2":
        # Acceptable, check cipher specifics
        pass
    elif tls_version == "TLS 1.3":
        # Optimal
        pass

    # 2. Cipher Suite & Encryption Checks
    enc = cipher_info["enc"].upper()
    if "3DES" in enc or "DES" in enc:
        warnings.append("3DES cipher suite in use; vulnerable to Sweet32 64-bit block collision attack (CVE-2016-2183).")
        risk = "HIGH" if risk != "CRITICAL" else risk
    elif "RC4" in enc:
        warnings.append("RC4 stream cipher is cryptographically broken and prohibited by RFC 7465.")
        risk = "CRITICAL"
    elif "CBC" in enc:
        warnings.append("CBC mode cipher suite detected; susceptible to padding oracle attacks (e.g. Lucky Thirteen, Zombie POODLE).")
        if risk == "LOW":
            risk = "MEDIUM"

    # 3. Key Exchange & Forward Secrecy Checks
    if not cipher_info["pfs"]:
        warnings.append("Missing Forward Secrecy (PFS): Static RSA key exchange allows retroactive decryption if server private key is compromised.")
        if risk == "LOW":
            risk = "MEDIUM"

    # 4. Hash / MAC checks
    mac = cipher_info["mac"].upper()
    if "MD5" in mac:
        warnings.append("MD5 MAC algorithm is cryptographically compromised with known collision attacks.")
        risk = "CRITICAL"
    elif "SHA1" in mac:
        warnings.append("SHA-1 integrity hash is deprecated due to theoretical and practical collision weaknesses.")
        if risk == "LOW":
            risk = "MEDIUM"

    return TLSHandshake(
        session_id=session_id,
        tls_version=tls_version,
        cipher_suite=cipher_suite,
        cipher_suite_hex=None,
        key_exchange=cipher_info["kex"],
        authentication=cipher_info["auth"],
        encryption_algorithm=cipher_info["enc"],
        mac_hash=cipher_info["mac"],
        forward_secrecy=cipher_info["pfs"],
        session_resumption=False,
        alpn=alpn,
        sni_server_name=sni,
        client_supported_versions=["TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0"] if "1.0" in tls_version else ["TLS 1.3", "TLS 1.2"],
        extensions=extensions,
        warnings=warnings,
        risk=risk
    )
