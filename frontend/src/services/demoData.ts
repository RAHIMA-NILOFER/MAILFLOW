import {
  PCAPAnalysis,
  EmailSession,
  TLSHandshake,
  Certificate,
  Finding,
  Anomaly,
  TimelineEvent,
  CommunicationStep
} from '../types';

export function createFullDemoAnalysis(): PCAPAnalysis {
  const baseTime = new Date('2026-09-28T14:30:00Z');

  // 1. Certificates
  const certificates: Certificate[] = [
    {
      id: 'CERT-001',
      session_id: 'SMTP-0042',
      subject_cn: 'mail.enterprise-corp.com',
      subject_o: 'Enterprise',
      issuer_cn: 'DigiCert Global TLS RSA4096 Root CA',
      issuer_o: 'DigiCert',
      serial_number: '04:A2:89:C1:90:3B:EE:74:10',
      fingerprint_sha256: '7F:8A:1C:99:3B:55:01:E2:DA:44:88:91:AC:5B:33:41:22:90:EE:11:55:77:88:99:AA:BB:CC:DD:EE:FF:00:11',
      valid_from: '2024-03-01T00:00:00Z',
      valid_until: '2025-08-15T23:59:59Z',
      days_remaining: -409,
      public_key_algorithm: 'RSA',
      key_length: 2048,
      signature_algorithm: 'sha256WithRSAEncryption',
      san_list: ['mail.enterprise-corp.com', 'smtp.enterprise-corp.com', 'mx1.enterprise-corp.com'],
      chain_status: 'COMPLETE',
      trust_status: 'EXPIRED',
      is_self_signed: false,
      is_expired: true,
      is_expiring_soon: false,
      chain_visualization: [
        { tier: 'Root CA', cn: 'DigiCert Global Root G2', status: 'TRUSTED', is_leaf: false },
        { tier: 'Intermediate CA', cn: 'DigiCert Global TLS RSA4096 Root CA', status: 'VALID', is_leaf: false },
        { tier: 'Server Certificate', cn: 'mail.enterprise-corp.com', status: 'EXPIRED', is_leaf: true },
      ],
      validation_checks: {
        format_valid: true,
        validity_period: false,
        hostname_san_match: true,
        chain_completeness: true,
        signature_algorithm_strength: true,
        public_key_strength: true,
        unexpired: false,
        trusted_root: true,
      },
      warnings: ['EXPIRED: Certificate validity window has elapsed.'],
      risk: 'CRITICAL',
    },
    {
      id: 'CERT-002',
      session_id: 'SMTP-0015',
      subject_cn: 'internal-relay.corp.local',
      subject_o: 'Enterprise',
      issuer_cn: 'internal-relay.corp.local',
      issuer_o: 'internal-relay',
      serial_number: '18:B9:44:FF:01:23:45:67:89',
      fingerprint_sha256: '12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0',
      valid_from: '2023-01-10T00:00:00Z',
      valid_until: '2028-01-10T23:59:59Z',
      days_remaining: 468,
      public_key_algorithm: 'RSA',
      key_length: 1024,
      signature_algorithm: 'sha1WithRSAEncryption',
      san_list: ['internal-relay.corp.local', 'mailrelay.local'],
      chain_status: 'SELF_SIGNED',
      trust_status: 'UNTRUSTED_SELF_SIGNED',
      is_self_signed: true,
      is_expired: false,
      is_expiring_soon: false,
      chain_visualization: [
        { tier: 'Root / Server', cn: 'internal-relay.corp.local', status: 'SELF_SIGNED', is_leaf: true },
      ],
      validation_checks: {
        format_valid: true,
        validity_period: true,
        hostname_san_match: true,
        chain_completeness: false,
        signature_algorithm_strength: false,
        public_key_strength: false,
        unexpired: true,
        trusted_root: false,
      },
      warnings: [
        'SELF-SIGNED: Certificate was issued by its own subject, lacking trusted CA verification.',
        'WEAK KEY: RSA key length of 1024 bits is insufficient (NIST SP 800-52r2 recommends >= 2048).',
        'WEAK SIGNATURE: SHA-1 signature algorithm is deprecated.',
      ],
      risk: 'CRITICAL',
    },
    {
      id: 'CERT-003',
      session_id: 'IMAP-0008',
      subject_cn: 'imap.cloudmail-gateway.net',
      subject_o: 'Gateway',
      issuer_cn: "Let's Encrypt Authority E6",
      issuer_o: "Let's Encrypt",
      serial_number: '03:FF:11:88:55:22:99:33:AA',
      fingerprint_sha256: 'CC:44:88:22:11:99:00:55:EE:77:AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF',
      valid_from: '2026-08-01T00:00:00Z',
      valid_until: '2026-10-10T23:59:59Z',
      days_remaining: 12,
      public_key_algorithm: 'ECDSA',
      key_length: 256,
      signature_algorithm: 'ecdsa-with-SHA256',
      san_list: ['imap.cloudmail-gateway.net', 'pop.cloudmail-gateway.net'],
      chain_status: 'COMPLETE',
      trust_status: 'TRUSTED_ROOT',
      is_self_signed: false,
      is_expired: false,
      is_expiring_soon: true,
      chain_visualization: [
        { tier: 'Root CA', cn: 'ISRG Root X1', status: 'TRUSTED', is_leaf: false },
        { tier: 'Intermediate CA', cn: "Let's Encrypt Authority E6", status: 'VALID', is_leaf: false },
        { tier: 'Server Certificate', cn: 'imap.cloudmail-gateway.net', status: 'VALID', is_leaf: true },
      ],
      validation_checks: {
        format_valid: true,
        validity_period: true,
        hostname_san_match: true,
        chain_completeness: true,
        signature_algorithm_strength: true,
        public_key_strength: true,
        unexpired: true,
        trusted_root: true,
      },
      warnings: ['EXPIRING SOON: Certificate expires in 12 days.'],
      risk: 'MEDIUM',
    },
    {
      id: 'CERT-004',
      session_id: 'SMTP-0001',
      subject_cn: 'mx.sentinel-security.org',
      subject_o: 'Sentinel',
      issuer_cn: 'DigiCert Global TLS RSA4096 Root CA',
      issuer_o: 'DigiCert',
      serial_number: '77:AA:BB:CC:DD:EE:11:22:33',
      fingerprint_sha256: '88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77',
      valid_from: '2026-01-01T00:00:00Z',
      valid_until: '2027-01-01T23:59:59Z',
      days_remaining: 94,
      public_key_algorithm: 'RSA',
      key_length: 4096,
      signature_algorithm: 'sha256WithRSAEncryption',
      san_list: ['mx.sentinel-security.org', 'mail.sentinel-security.org', 'smtp.sentinel-security.org'],
      chain_status: 'COMPLETE',
      trust_status: 'TRUSTED_ROOT',
      is_self_signed: false,
      is_expired: false,
      is_expiring_soon: false,
      chain_visualization: [
        { tier: 'Root CA', cn: 'DigiCert Global Root G2', status: 'TRUSTED', is_leaf: false },
        { tier: 'Intermediate CA', cn: 'DigiCert Global TLS RSA4096 Root CA', status: 'VALID', is_leaf: false },
        { tier: 'Server Certificate', cn: 'mx.sentinel-security.org', status: 'VALID', is_leaf: true },
      ],
      validation_checks: {
        format_valid: true,
        validity_period: true,
        hostname_san_match: true,
        chain_completeness: true,
        signature_algorithm_strength: true,
        public_key_strength: true,
        unexpired: true,
        trusted_root: true,
      },
      warnings: [],
      risk: 'LOW',
    },
    {
      id: 'CERT-005',
      session_id: 'POP3-0004',
      subject_cn: 'pop3.legacy-branch.com',
      subject_o: 'Branch',
      issuer_cn: 'Sectigo RSA Domain Validation Secure Server CA',
      issuer_o: 'Sectigo',
      serial_number: '99:88:77:66:55:44:33:22:11',
      fingerprint_sha256: '44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33',
      valid_from: '2025-05-10T00:00:00Z',
      valid_until: '2026-11-20T23:59:59Z',
      days_remaining: 53,
      public_key_algorithm: 'RSA',
      key_length: 2048,
      signature_algorithm: 'sha256WithRSAEncryption',
      san_list: ['pop3.legacy-branch.com'],
      chain_status: 'INCOMPLETE',
      trust_status: 'UNTRUSTED_CHAIN',
      is_self_signed: false,
      is_expired: false,
      is_expiring_soon: false,
      chain_visualization: [
        { tier: 'Root CA', cn: 'USERTrust RSA Certification Authority', status: 'TRUSTED', is_leaf: false },
        { tier: 'Intermediate CA', cn: 'Sectigo RSA Domain Validation CA', status: 'MISSING', is_leaf: false },
        { tier: 'Server Certificate', cn: 'pop3.legacy-branch.com', status: 'VALID', is_leaf: true },
      ],
      validation_checks: {
        format_valid: true,
        validity_period: true,
        hostname_san_match: true,
        chain_completeness: false,
        signature_algorithm_strength: true,
        public_key_strength: true,
        unexpired: true,
        trusted_root: false,
      },
      warnings: ['INCOMPLETE CHAIN: Intermediate CA certificates were omitted in the TLS server certificate handshake.'],
      risk: 'HIGH',
    },
  ];

  // Helper for ladder diagrams
  const makeLadder = (proto: string, starttls: boolean, tlsVer: string, status: string): CommunicationStep[] => {
    const steps: CommunicationStep[] = [
      { step_number: 1, sender: 'Client', protocol_layer: 'TCP', command_or_status: 'SYN (Port 25/587/143)', is_encrypted: false, timestamp_offset_ms: 0.0, description: 'Initial TCP 3-Way Handshake SYN segment', raw_payload_snippet: '[TCP SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256' },
      { step_number: 2, sender: 'Server', protocol_layer: 'TCP', command_or_status: 'SYN-ACK', is_encrypted: false, timestamp_offset_ms: 14.2, description: 'TCP Handshake SYN-ACK acknowledgment', raw_payload_snippet: '[TCP SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0' },
      { step_number: 3, sender: 'Client', protocol_layer: 'TCP', command_or_status: 'ACK', is_encrypted: false, timestamp_offset_ms: 15.3, description: 'TCP Handshake established (3-Way Completed)', raw_payload_snippet: '[TCP ACK] Seq=1 Ack=1 Win=64240 Len=0' },
    ];

    if (proto === 'SMTP') {
      steps.push(
        { step_number: 4, sender: 'Server', protocol_layer: 'SMTP', command_or_status: '220 mail.corp.net ESMTP Postfix Service Ready', is_encrypted: false, timestamp_offset_ms: 23.8, description: 'Server Banner advertisement', raw_payload_snippet: '220 mail.corp.net ESMTP Postfix (Ubuntu)\\r\\n' },
        { step_number: 5, sender: 'Client', protocol_layer: 'SMTP', command_or_status: 'EHLO gateway.client-net.org', is_encrypted: false, timestamp_offset_ms: 35.8, description: 'Client Extended HELO greeting', raw_payload_snippet: 'EHLO gateway.client-net.org\\r\\n' },
        { step_number: 6, sender: 'Server', protocol_layer: 'SMTP', command_or_status: '250-STARTTLS (8BITMIME / SIZE 35882000)', is_encrypted: false, timestamp_offset_ms: 45.2, description: 'Server announces STARTTLS capability', raw_payload_snippet: '250-mail.corp.net\\r\\n250-STARTTLS\\r\\n250-PIPELINING\\r\\n' }
      );
      if (starttls && status !== 'DOWNGRADED') {
        steps.push(
          { step_number: 7, sender: 'Client', protocol_layer: 'SMTP', command_or_status: 'STARTTLS', is_encrypted: false, timestamp_offset_ms: 56.4, description: 'Client requests cryptographic upgrade to TLS', raw_payload_snippet: 'STARTTLS\\r\\n' },
          { step_number: 8, sender: 'Server', protocol_layer: 'SMTP', command_or_status: '220 2.0.0 Ready to start TLS', is_encrypted: false, timestamp_offset_ms: 65.1, description: 'Server acknowledges TLS readiness; switches to TLS record layer', raw_payload_snippet: '220 2.0.0 Ready to start TLS\\r\\n' },
          { step_number: 9, sender: 'Client', protocol_layer: 'TLS', command_or_status: `ClientHello (${tlsVer})`, is_encrypted: false, timestamp_offset_ms: 79.6, description: 'TLS ClientHello advertising cipher suites & supported extensions', raw_payload_snippet: `TLS Record Layer: Handshake Protocol: Client Hello (Version: ${tlsVer})` },
          { step_number: 10, sender: 'Server', protocol_layer: 'TLS', command_or_status: 'ServerHello + Certificate + ServerKeyExchange + Done', is_encrypted: false, timestamp_offset_ms: 101.6, description: 'Server selects cipher suite and transmits X.509 certificate chain', raw_payload_snippet: 'TLS Record Layer: Handshake Protocol: Server Hello, Certificate' },
          { step_number: 11, sender: 'Client', protocol_layer: 'TLS', command_or_status: 'ClientKeyExchange + ChangeCipherSpec + Finished', is_encrypted: true, timestamp_offset_ms: 123.6, description: 'Key exchange negotiated; transition to encrypted record stream', raw_payload_snippet: 'TLS Record Layer: Handshake Protocol: Encrypted Handshake Message' },
          { step_number: 12, sender: 'Client', protocol_layer: 'SMTP (Encrypted)', command_or_status: '[TLS Application Data: MAIL FROM / RCPT TO / DATA payload]', is_encrypted: true, timestamp_offset_ms: 138.6, description: 'Encrypted email transaction payload transmission', raw_payload_snippet: '[Encrypted Application Data: 4,096 bytes AES-GCM]' }
        );
      } else if (status === 'DOWNGRADED') {
        steps.push(
          { step_number: 7, sender: 'Client', protocol_layer: 'SMTP', command_or_status: 'STARTTLS', is_encrypted: false, timestamp_offset_ms: 56.4, description: 'Client requests STARTTLS upgrade', raw_payload_snippet: 'STARTTLS\\r\\n' },
          { step_number: 8, sender: 'Server', protocol_layer: 'SMTP', command_or_status: '454 4.7.0 TLS not available due to temporary reason', is_encrypted: false, timestamp_offset_ms: 71.6, description: 'Server rejects TLS upgrade (STARTTLS Downgrade / Stripping)', raw_payload_snippet: '454 4.7.0 TLS not available due to temporary reason\\r\\n' },
          { step_number: 9, sender: 'Client', protocol_layer: 'SMTP', command_or_status: 'MAIL FROM:<ceo@enterprise-corp.com> (Insecure Fallback)', is_encrypted: false, timestamp_offset_ms: 81.7, description: 'Client fell back to unencrypted transmission!', raw_payload_snippet: 'MAIL FROM:<ceo@enterprise-corp.com>\\r\\n' }
        );
      }
    } else if (proto === 'IMAP') {
      steps.push(
        { step_number: 4, sender: 'Server', protocol_layer: 'IMAP', command_or_status: '* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN] Dovecot ready.', is_encrypted: false, timestamp_offset_ms: 23.8, description: 'IMAP Greeting banner with STARTTLS capability', raw_payload_snippet: '* OK [CAPABILITY IMAP4rev1 STARTTLS] IMAP4rev1 Server\\r\\n' }
      );
      if (starttls) {
        steps.push(
          { step_number: 5, sender: 'Client', protocol_layer: 'IMAP', command_or_status: '. STARTTLS', is_encrypted: false, timestamp_offset_ms: 35.8, description: 'IMAP Client initiates STARTTLS command', raw_payload_snippet: '. STARTTLS\\r\\n' },
          { step_number: 6, sender: 'Server', protocol_layer: 'IMAP', command_or_status: '. OK Begin TLS negotiation now', is_encrypted: false, timestamp_offset_ms: 45.3, description: 'IMAP server signals TLS readiness', raw_payload_snippet: '. OK Begin TLS negotiation now\\r\\n' },
          { step_number: 7, sender: 'Client', protocol_layer: 'TLS', command_or_status: `ClientHello (${tlsVer})`, is_encrypted: false, timestamp_offset_ms: 63.3, description: 'TLS ClientHello over IMAP stream', raw_payload_snippet: `TLS Handshake Client Hello (${tlsVer})` },
          { step_number: 8, sender: 'Server', protocol_layer: 'TLS', command_or_status: 'ServerHello + Certificate + Handshake Done', is_encrypted: false, timestamp_offset_ms: 83.3, description: 'TLS Handshake negotiated successfully', raw_payload_snippet: 'TLS Handshake Server Hello, Certificate' },
          { step_number: 9, sender: 'Client', protocol_layer: 'IMAP (Encrypted)', command_or_status: '[TLS Application Data: Authenticated Fetch / Sync]', is_encrypted: true, timestamp_offset_ms: 98.3, description: 'Encrypted IMAP mailbox synchronization', raw_payload_snippet: '[Encrypted Application Data]' }
        );
      } else {
        steps.push(
          { step_number: 5, sender: 'Client', protocol_layer: 'IMAP', command_or_status: 'A001 LOGIN user@corp.net P@ssw0rd123! (Cleartext Exposure)', is_encrypted: false, timestamp_offset_ms: 35.8, description: 'Plaintext IMAP credentials transmitted without encryption!', raw_payload_snippet: 'A001 LOGIN user@corp.net P@ssw0rd123!\\r\\n' }
        );
      }
    } else {
      steps.push(
        { step_number: 4, sender: 'Server', protocol_layer: 'POP3', command_or_status: '+OK POP3 server ready <1892.671@mail.corp.com>', is_encrypted: false, timestamp_offset_ms: 23.8, description: 'POP3 Server Greeting', raw_payload_snippet: '+OK POP3 server ready\\r\\n' }
      );
      if (starttls) {
        steps.push(
          { step_number: 5, sender: 'Client', protocol_layer: 'POP3', command_or_status: 'STLS', is_encrypted: false, timestamp_offset_ms: 37.8, description: 'POP3 STLS command', raw_payload_snippet: 'STLS\\r\\n' },
          { step_number: 6, sender: 'Server', protocol_layer: 'POP3', command_or_status: '+OK Begin TLS negotiation', is_encrypted: false, timestamp_offset_ms: 47.8, description: 'Server switches to TLS', raw_payload_snippet: '+OK Begin TLS negotiation\\r\\n' },
          { step_number: 7, sender: 'Client', protocol_layer: 'TLS', command_or_status: `TLS Handshake (${tlsVer})`, is_encrypted: false, timestamp_offset_ms: 67.8, description: 'POP3 TLS Handshake completed', raw_payload_snippet: `TLS Handshake Protocol (${tlsVer})` },
          { step_number: 8, sender: 'Client', protocol_layer: 'POP3 (Encrypted)', command_or_status: '[TLS Application Data: POP3 RETR]', is_encrypted: true, timestamp_offset_ms: 82.8, description: 'Encrypted POP3 message retrieval', raw_payload_snippet: '[Encrypted Application Data]' }
        );
      } else {
        steps.push(
          { step_number: 5, sender: 'Client', protocol_layer: 'POP3', command_or_status: 'USER sales@corp.net / PASS SecretPass99', is_encrypted: false, timestamp_offset_ms: 37.8, description: 'Plaintext POP3 user authentication', raw_payload_snippet: 'USER sales@corp.net\\r\\nPASS SecretPass99\\r\\n' }
        );
      }
    }
    return steps;
  };

  // 2. Archetype sessions
  const sessions: EmailSession[] = [];
  const tlsHandshakes: TLSHandshake[] = [];

  const archetypes = [
    {
      id: 'SMTP-0042', proto: 'SMTP' as const, src_ip: '192.168.10.45', src_port: 49182,
      dst_ip: '10.0.5.25', dst_port: 25, client_host: 'mail.enterprise-corp.com',
      banner: '220 mail.enterprise-corp.com ESMTP Postfix', starttls: true,
      tls_ver: 'TLS 1.0', cipher: 'DES-CBC3-SHA', cert_id: 'CERT-001',
      risk: 'CRITICAL' as const, status: 'ENCRYPTED' as const, duration: 4820, pkts: 612, bytes: 482910,
      flags: ['Deprecated TLS 1.0', 'Weak 3DES Cipher', 'Expired X.509 Cert', 'No Forward Secrecy'],
      risk_factors: ['+25 TLS 1.0 Deprecation', '+20 3DES Sweet32', '+20 Expired Certificate', '+10 Static RSA No PFS'],
      risk_score: 94,
    },
    {
      id: 'SMTP-0015', proto: 'SMTP' as const, src_ip: '192.168.10.88', src_port: 51230,
      dst_ip: '10.0.5.30', dst_port: 587, client_host: 'internal-relay.corp.local',
      banner: '220 internal-relay.corp.local ESMTP Exim 4.94', starttls: true,
      tls_ver: 'TLS 1.1', cipher: 'RC4-SHA', cert_id: 'CERT-002',
      risk: 'CRITICAL' as const, status: 'ENCRYPTED' as const, duration: 3100, pkts: 418, bytes: 312050,
      flags: ['Deprecated TLS 1.1', 'Broken RC4 Stream Cipher', 'Self-Signed Certificate', 'Weak 1024-bit RSA Key', 'SHA-1 Signature'],
      risk_factors: ['+25 TLS 1.1 Deprecation', '+20 Insecure RC4', '+15 Self-Signed Cert', '+12 Weak 1024-bit Key', '+10 SHA-1 Hash'],
      risk_score: 96,
    },
    {
      id: 'IMAP-0008', proto: 'IMAP' as const, src_ip: '172.16.20.12', src_port: 54890,
      dst_ip: '10.0.5.143', dst_port: 143, client_host: 'imap.cloudmail-gateway.net',
      banner: '* OK Dovecot IMAP ready', starttls: true,
      tls_ver: 'TLS 1.2', cipher: 'ECDHE-RSA-AES256-GCM-SHA384', cert_id: 'CERT-003',
      risk: 'MEDIUM' as const, status: 'ENCRYPTED' as const, duration: 1850, pkts: 310, bytes: 184500,
      flags: ['Certificate Expiring in 12 Days', 'Modern TLS 1.2 AEAD'],
      risk_factors: ['+15 Certificate Expiring Soon (12 days)', '+0 Modern ECDHE-GCM'],
      risk_score: 42,
    },
    {
      id: 'SMTP-0001', proto: 'SMTP' as const, src_ip: '192.168.1.100', src_port: 44102,
      dst_ip: '10.0.5.25', dst_port: 25, client_host: 'mx.sentinel-security.org',
      banner: '220 mx.sentinel-security.org ESMTP Postfix Ready', starttls: true,
      tls_ver: 'TLS 1.3', cipher: 'TLS_AES_256_GCM_SHA384', cert_id: 'CERT-004',
      risk: 'LOW' as const, status: 'ENCRYPTED' as const, duration: 820, pkts: 240, bytes: 98400,
      flags: ['TLS 1.3 Best Practice', 'Forward Secrecy Verified', 'Modern AEAD', 'Valid Certificate'],
      risk_factors: ['+0 Optimal Cryptographic Posture'],
      risk_score: 8,
    },
    {
      id: 'SMTP-0077', proto: 'SMTP' as const, src_ip: '192.168.10.99', src_port: 50110,
      dst_ip: '10.0.5.25', dst_port: 25, client_host: 'outbound-relay.vendor.com',
      banner: '220 mail.corp.net ESMTP', starttls: true,
      tls_ver: undefined, cipher: undefined, cert_id: undefined,
      risk: 'CRITICAL' as const, status: 'DOWNGRADED' as const, duration: 2200, pkts: 190, bytes: 67000,
      flags: ['STARTTLS Stripping Downgrade', 'Cleartext Transmission'],
      risk_factors: ['+25 STARTTLS Downgrade Error 454', '+20 Cleartext Fallback'],
      risk_score: 92,
    },
    {
      id: 'POP3-0004', proto: 'POP3' as const, src_ip: '172.16.30.5', src_port: 48210,
      dst_ip: '10.0.5.110', dst_port: 110, client_host: 'pop3.legacy-branch.com',
      banner: '+OK POP3 Server Ready', starttls: true,
      tls_ver: 'TLS 1.2', cipher: 'AES128-SHA256', cert_id: 'CERT-005',
      risk: 'HIGH' as const, status: 'ENCRYPTED' as const, duration: 1450, pkts: 210, bytes: 112000,
      flags: ['Missing Forward Secrecy (Static RSA)', 'Incomplete Intermediate Cert Chain', 'CBC Mode Cipher'],
      risk_factors: ['+15 No PFS (Static RSA)', '+12 Incomplete Chain', '+10 CBC Cipher Suite'],
      risk_score: 68,
    },
    {
      id: 'IMAP-0021', proto: 'IMAP' as const, src_ip: '192.168.20.15', src_port: 52900,
      dst_ip: '10.0.5.143', dst_port: 143, client_host: 'imap.internal.local',
      banner: '* OK IMAP4rev1 Ready', starttls: false,
      tls_ver: undefined, cipher: undefined, cert_id: undefined,
      risk: 'HIGH' as const, status: 'PLAINTEXT' as const, duration: 940, pkts: 120, bytes: 45000,
      flags: ['No Encryption (Plaintext IMAP)', 'Credentials Exposed'],
      risk_factors: ['+20 Missing STARTTLS', '+15 Cleartext Auth Commands'],
      risk_score: 75,
    },
  ];

  let smtpCount = 0;
  let imapCount = 0;
  let pop3Count = 0;

  for (let i = 1; i <= 127; i++) {
    const offsetMs = i * 18 * 1000;
    const startStr = new Date(baseTime.getTime() + offsetMs).toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
    const endStr = new Date(baseTime.getTime() + offsetMs + 2000).toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

    let proto: 'SMTP' | 'IMAP' | 'POP3' = 'SMTP';
    let dstPort = 25;

    if (smtpCount < 61) {
      proto = 'SMTP';
      smtpCount++;
      dstPort = smtpCount % 3 !== 0 ? 25 : 587;
    } else if (imapCount < 44) {
      proto = 'IMAP';
      imapCount++;
      dstPort = imapCount % 4 !== 0 ? 143 : 993;
    } else {
      proto = 'POP3';
      pop3Count++;
      dstPort = pop3Count % 3 !== 0 ? 110 : 995;
    }

    if (i <= archetypes.length) {
      const arch = archetypes[i - 1];
      const sObj: EmailSession = {
        session_id: arch.id,
        protocol: arch.proto,
        source_ip: arch.src_ip,
        source_port: arch.src_port,
        dest_ip: arch.dst_ip,
        dest_port: arch.dst_port,
        client_hostname: arch.client_host,
        server_banner: arch.banner,
        starttls_requested: arch.starttls,
        starttls_success: arch.status === 'ENCRYPTED',
        tls_version: arch.tls_ver,
        cipher_suite: arch.cipher,
        certificate_subject: arch.cert_id ? 'mail.enterprise-corp.com' : undefined,
        certificate_id: arch.cert_id,
        risk: arch.risk,
        status: arch.status,
        start_time: startStr,
        end_time: endStr,
        duration_ms: arch.duration,
        packet_count: arch.pkts,
        byte_count: arch.bytes,
        communication_flow: makeLadder(arch.proto, arch.starttls, arch.tls_ver || 'TLS 1.3', arch.status),
        flags: arch.flags,
        explainable_risk_factors: arch.risk_factors,
        risk_score: arch.risk_score,
      };
      sessions.push(sObj);

      if (arch.tls_ver) {
        tlsHandshakes.push({
          session_id: arch.id,
          tls_version: arch.tls_ver,
          cipher_suite: arch.cipher || 'TLS_AES_256_GCM_SHA384',
          key_exchange: arch.cipher?.includes('ECDHE') ? 'ECDHE (X25519)' : (arch.cipher?.includes('DES') || arch.cipher?.includes('RC4') ? 'RSA (Static)' : 'ECDHE'),
          authentication: 'RSA-PSS',
          encryption_algorithm: arch.cipher?.includes('3DES') ? '3DES-CBC' : (arch.cipher?.includes('RC4') ? 'RC4' : 'AES-256-GCM'),
          mac_hash: arch.cipher?.includes('SHA384') ? 'SHA384' : (arch.cipher?.includes('SHA1') ? 'SHA1' : 'AEAD'),
          forward_secrecy: !arch.cipher?.includes('DES') && !arch.cipher?.includes('RC4') && !arch.cipher?.includes('AES128-SHA'),
          session_resumption: false,
          alpn: arch.proto.toLowerCase(),
          sni_server_name: arch.client_host,
          client_supported_versions: ['TLS 1.3', 'TLS 1.2'],
          extensions: ['server_name', 'supported_groups', 'signature_algorithms', 'application_layer_protocol_negotiation'],
          warnings: arch.flags.filter(f => f.includes('Deprecated') || f.includes('Weak') || f.includes('No Forward')),
          risk: arch.risk,
        });
      }
    } else {
      const sId = `${proto}-${String(i).padStart(4, '0')}`;
      const srcIp = `192.168.10.${(i % 150) + 10}`;
      const srcPort = 45000 + i;
      const dstIp = `10.0.5.${proto === 'SMTP' ? 25 : proto === 'IMAP' ? 143 : 110}`;
      const isTLS = i <= 109;
      const tlsVer = isTLS ? (i % 5 === 0 ? 'TLS 1.2' : i % 7 === 0 ? 'TLS 1.2' : 'TLS 1.3') : undefined;
      const cipher = isTLS ? (i % 5 === 0 ? 'ECDHE-RSA-AES128-GCM-SHA256' : i % 7 === 0 ? 'AES256-GCM-SHA384' : 'TLS_AES_256_GCM_SHA384') : undefined;
      const riskLevel = isTLS ? (i % 7 === 0 ? 'MEDIUM' : 'LOW') : (proto === 'SMTP' ? 'MEDIUM' : 'HIGH');
      const status = isTLS ? 'ENCRYPTED' : 'PLAINTEXT';

      const sObj: EmailSession = {
        session_id: sId,
        protocol: proto,
        source_ip: srcIp,
        source_port: srcPort,
        dest_ip: dstIp,
        dest_port: dstPort,
        client_hostname: `client-${i}.corp.net`,
        server_banner: `220 ${proto.toLowerCase()}.corp.net ESMTP Ready`,
        starttls_requested: isTLS,
        starttls_success: isTLS,
        tls_version: tlsVer,
        cipher_suite: cipher,
        certificate_subject: isTLS ? 'mx.sentinel-security.org' : undefined,
        certificate_id: isTLS ? 'CERT-004' : undefined,
        risk: riskLevel,
        status: status,
        start_time: startStr,
        end_time: endStr,
        duration_ms: 650 + (i * 15) % 2200,
        packet_count: 180 + (i * 7) % 350,
        byte_count: (180 + (i * 7) % 350) * 840,
        communication_flow: makeLadder(proto, isTLS, tlsVer || 'TLS 1.3', status),
        flags: isTLS ? ['Standard TLS Security', 'PFS Active'] : ['Cleartext Transmission', 'Missing STARTTLS'],
        explainable_risk_factors: isTLS ? ['+0 Compliant TLS Policy'] : [`+15 Plaintext ${proto} Port ${dstPort}`],
        risk_score: isTLS ? (i % 7 === 0 ? 38 : 8) : 65,
      };
      sessions.push(sObj);

      if (isTLS && tlsVer) {
        tlsHandshakes.push({
          session_id: sId,
          tls_version: tlsVer,
          cipher_suite: cipher || 'TLS_AES_256_GCM_SHA384',
          key_exchange: cipher?.includes('AES256-GCM') ? 'RSA (Static)' : 'ECDHE (X25519)',
          authentication: 'RSA-PSS',
          encryption_algorithm: 'AES-256-GCM',
          mac_hash: 'AEAD',
          forward_secrecy: !cipher?.includes('AES256-GCM'),
          session_resumption: false,
          alpn: proto.toLowerCase(),
          sni_server_name: `client-${i}.corp.net`,
          client_supported_versions: ['TLS 1.3', 'TLS 1.2'],
          extensions: ['server_name', 'supported_groups', 'signature_algorithms'],
          warnings: cipher?.includes('AES256-GCM') ? ['Missing Perfect Forward Secrecy (Static RSA)'] : [],
          risk: riskLevel,
        });
      }
    }
  }

  // 3. Findings
  const findings: Finding[] = [
    {
      id: 'CRYPTO-001',
      title: 'Deprecated TLS 1.0 Version Protocol In Use',
      severity: 'HIGH',
      category: 'TLS Configuration',
      session_id: 'SMTP-0042',
      protocol: 'SMTP',
      evidence_observed: 'Observed: TLS 1.0 (ServerHello negotiation)',
      expected_secure: 'TLS 1.2 or TLS 1.3 (RFC 8996 compliance)',
      evidence_detail: 'Client and Server negotiated TLS 1.0. This protocol version lacks modern AEAD ciphers and is deprecated by IETF RFC 8996.',
      packet_stream_ref: 'ServerHello Record (Session SMTP-0042)',
      impact: 'Susceptibility to cryptographic downgrade attacks, BEAST (CVE-2011-3389), and POODLE vulnerabilities.',
      recommendation: 'Disable TLS 1.0, TLS 1.1, and SSL 3.0 on mail server daemons. Enforce minimum TLS 1.2.',
      cwe_id: 'CWE-326',
      cvss_score: 7.5,
      status: 'OPEN',
    },
    {
      id: 'CRYPTO-002',
      title: 'Weak 64-bit Block Cipher Suite (3DES Sweet32)',
      severity: 'HIGH',
      category: 'Cipher Suite',
      session_id: 'SMTP-0042',
      protocol: 'SMTP',
      evidence_observed: 'Cipher Suite: DES-CBC3-SHA (3DES-CBC)',
      expected_secure: 'AES-GCM (128/256) or ChaCha20-Poly1305 AEAD suites',
      evidence_detail: '3DES uses a 64-bit block size. Birthday attacks allow plaintext recovery after capturing roughly 32GB of data over the same TLS session (CVE-2016-2183).',
      packet_stream_ref: 'CipherSuite Negotiation (Session SMTP-0042)',
      impact: 'Passive adversary with high packet capture volume can decrypt session authentication tokens.',
      recommendation: 'Remove 3DES and all DES-based ciphers from the server cipher suite list.',
      cwe_id: 'CWE-327',
      cvss_score: 7.1,
      status: 'OPEN',
    },
    {
      id: 'CRYPTO-003',
      title: 'Expired X.509 Certificate in TLS Handshake',
      severity: 'CRITICAL',
      category: 'Certificate',
      session_id: 'SMTP-0042',
      protocol: 'SMTP',
      evidence_observed: 'Valid Until: 2025-08-15 (409 days overdue)',
      expected_secure: 'Active, unexpired certificate with valid automated renewal',
      evidence_detail: 'Certificate for CN=mail.enterprise-corp.com expired. Connecting MTAs will either fail delivery or bypass trust checks.',
      packet_stream_ref: 'Certificate Message (Session SMTP-0042)',
      impact: 'Connection dropouts, delivery failures, or users habituated into accepting invalid security certificates.',
      recommendation: 'Renew the TLS certificate immediately using an ACME automated provider (Certbot / Let\'s Encrypt) or enterprise PKI.',
      cwe_id: 'CWE-298',
      cvss_score: 8.2,
      status: 'OPEN',
    },
    {
      id: 'CRYPTO-004',
      title: 'Prohibited RC4 Stream Cipher In Use',
      severity: 'CRITICAL',
      category: 'Cipher Suite',
      session_id: 'SMTP-0015',
      protocol: 'SMTP',
      evidence_observed: 'Cipher Suite: RC4-SHA',
      expected_secure: 'Modern AEAD Ciphers (AES-256-GCM, AES-128-GCM)',
      evidence_detail: 'RC4 has known biometric single-byte biases and keystream vulnerabilities prohibited by RFC 7465.',
      packet_stream_ref: 'CipherSuite Negotiation (Session SMTP-0015)',
      impact: 'Full stream decryption possibility via statistical keystream biases.',
      recommendation: 'Immediately disable RC4 suites across all mail server configurations.',
      cwe_id: 'CWE-327',
      cvss_score: 9.1,
      status: 'OPEN',
    },
    {
      id: 'CRYPTO-005',
      title: 'Untrusted Self-Signed Certificate Detected',
      severity: 'HIGH',
      category: 'Certificate',
      session_id: 'SMTP-0015',
      protocol: 'SMTP',
      evidence_observed: 'Subject CN (internal-relay.corp.local) matches Issuer CN',
      expected_secure: 'Publicly trusted Certificate Authority or verified Enterprise PKI CA',
      evidence_detail: 'Self-signed certificates cannot be verified by remote MTAs and allow undetected passive/active interception.',
      packet_stream_ref: 'Certificate Chain (Session SMTP-0015)',
      impact: 'Lack of identity assurance, mail client warning popups, and MITM vulnerability.',
      recommendation: 'Replace self-signed certificates with certificates issued by a trusted public CA or properly installed internal trust anchor.',
      cwe_id: 'CWE-295',
      cvss_score: 7.4,
      status: 'OPEN',
    },
    {
      id: 'CRYPTO-006',
      title: 'Insecure STARTTLS Stripping / Downgrade Detected',
      severity: 'CRITICAL',
      category: 'STARTTLS',
      session_id: 'SMTP-0077',
      protocol: 'SMTP',
      evidence_observed: 'Server capability responded with 454 error code, falling back to cleartext',
      expected_secure: 'Require TLS (RFC 8461 MTA-STS / DANE TLSA enforcement)',
      evidence_detail: 'The client attempted STARTTLS negotiation, but traffic fell back to unencrypted transmission.',
      packet_stream_ref: 'TCP Stream SMTP-0077 (Handshake transition sequence)',
      impact: 'Active adversary stripping protection or severe configuration flaw exposing email transit in plaintext.',
      recommendation: 'Configure strict MTA-STS (Mail Transfer Agent Strict Transport Security) to prevent opportunistic downgrade attacks.',
      cwe_id: 'CWE-757',
      cvss_score: 8.9,
      status: 'OPEN',
    },
    {
      id: 'CRYPTO-007',
      title: 'Missing Perfect Forward Secrecy (Static RSA Key Exchange)',
      severity: 'MEDIUM',
      category: 'Key Exchange',
      session_id: 'POP3-0004',
      protocol: 'POP3',
      evidence_observed: 'Key Exchange: RSA (No (EC)DHE negotiated)',
      expected_secure: 'Ephemeral Diffie-Hellman (ECDHE / DHE) Key Exchange',
      evidence_detail: 'Static RSA key exchange does not provide Perfect Forward Secrecy. If the server\'s private key is compromised, historic PCAPs can be decrypted.',
      packet_stream_ref: 'ClientKeyExchange Record (Session POP3-0004)',
      impact: 'Loss of retroactive confidentiality for stored PCAP captures if certificates are compromised.',
      recommendation: 'Configure mail services to prefer ECDHE key exchange curves (X25519, secp256r1).',
      cwe_id: 'CWE-327',
      cvss_score: 5.9,
      status: 'OPEN',
    },
  ];

  // 4. Anomalies
  const anomalies: Anomaly[] = [
    {
      id: 'ANOM-001',
      anomaly_type: 'Unexpected TLS Downgrade',
      session_id: 'SMTP-0042',
      protocol: 'SMTP',
      anomaly_score: 88,
      confidence: 'HIGH',
      severity: 'HIGH',
      evidence: 'Client offered TLS 1.3/1.2 support but session negotiated TLS 1.0',
      explanation: 'Handshake negotiation fell back to an insecure legacy version despite modern client capabilities, characteristic of STARTTLS stripping or an active downgrade proxy.',
      timestamp: '2026-09-28 14:30:18 UTC',
    },
    {
      id: 'ANOM-002',
      anomaly_type: 'Rare / Obsolete Cipher Suite Selection',
      session_id: 'SMTP-0015',
      protocol: 'SMTP',
      anomaly_score: 76,
      confidence: 'HIGH',
      severity: 'HIGH',
      evidence: 'Negotiated Cipher: RC4-SHA',
      explanation: 'Observed cipher suite is in the bottom 0.5% of modern enterprise email traffic. May indicate legacy automated script or misconfigured relay daemon.',
      timestamp: '2026-09-28 14:31:45 UTC',
    },
    {
      id: 'ANOM-003',
      anomaly_type: 'Plaintext Authentication Credentials Exposure',
      session_id: 'IMAP-0021',
      protocol: 'IMAP',
      anomaly_score: 94,
      confidence: 'HIGH',
      severity: 'CRITICAL',
      evidence: 'IMAP LOGIN / AUTH command observed over unencrypted TCP connection',
      explanation: 'Mail client attempted user authentication without prior STARTTLS command, exposing cleartext credentials over passive wiretap.',
      timestamp: '2026-09-28 14:34:22 UTC',
    },
  ];

  // 5. Timeline
  const timeline: TimelineEvent[] = [
    {
      id: 'EVT-01',
      timestamp: '2026-09-28 14:30:18 UTC',
      session_id: 'SMTP-0042',
      protocol: 'SMTP',
      event_type: 'CRYPTOGRAPHIC_DEPRECATION',
      severity: 'critical',
      title: 'Deprecated TLS 1.0 & 3DES Suite Handshake Negotiated',
      description: 'Client 192.168.10.45 negotiated TLS 1.0 with 3DES-CBC3-SHA cipher suite and expired X.509 certificate.',
      source_ip: '192.168.10.45',
      dest_ip: '10.0.5.25',
    },
    {
      id: 'EVT-02',
      timestamp: '2026-09-28 14:31:45 UTC',
      session_id: 'SMTP-0015',
      protocol: 'SMTP',
      event_type: 'WEAK_CIPHER_AND_KEY',
      severity: 'critical',
      title: 'Prohibited RC4 Stream Cipher & 1024-bit RSA Key Observed',
      description: 'Client 192.168.10.88 negotiated RC4-SHA with a self-signed 1024-bit RSA certificate on submission port 587.',
      source_ip: '192.168.10.88',
      dest_ip: '10.0.5.30',
    },
    {
      id: 'EVT-03',
      timestamp: '2026-09-28 14:33:10 UTC',
      session_id: 'SMTP-0077',
      protocol: 'SMTP',
      event_type: 'STARTTLS_DOWNGRADE',
      severity: 'critical',
      title: 'STARTTLS Stripping / Downgrade Failure',
      description: 'Mail client attempted STARTTLS upgrade, server returned 454 error code; traffic reverted to unencrypted cleartext.',
      source_ip: '192.168.10.99',
      dest_ip: '10.0.5.25',
    },
    {
      id: 'EVT-04',
      timestamp: '2026-09-28 14:34:22 UTC',
      session_id: 'IMAP-0021',
      protocol: 'IMAP',
      event_type: 'CLEARTEXT_AUTH_LEAK',
      severity: 'high',
      title: 'Plaintext IMAP User Authentication Credentials Exposed',
      description: 'User authentication command sent over unencrypted TCP session without prior STARTTLS activation.',
      source_ip: '192.168.20.15',
      dest_ip: '10.0.5.143',
    },
  ];

  return {
    id: 'ANALYSIS-DEMO-001',
    filename: 'enterprise_mail_capture.pcap',
    file_size_bytes: 48392000,
    file_size_formatted: '46.15 MB',
    sha256_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    upload_timestamp: '2026-09-28 14:30:00 UTC',
    analysis_duration_seconds: 3.42,
    is_demo: true,
    status: 'COMPLETED',
    total_packets: 48392,
    total_email_sessions: 127,
    total_tls_sessions: 109,
    total_starttls_sessions: 103,
    total_certificates: certificates.length,
    critical_findings_count: 3,
    high_findings_count: 12,
    medium_findings_count: 18,
    low_findings_count: 94,
    security_score: 71,
    protocol_distribution: { smtp: 61, imap: 44, pop3: 22 },
    tls_version_distribution: { tls13: 78, tls12: 24, tls11: 4, tls10: 3, ssl_unknown: 18 },
    risk_distribution: { critical: 3, high: 12, medium: 18, low: 94, info: 0 },
    crypto_weakness_stats: {
      deprecated_tls: 7,
      weak_cipher: 5,
      cert_expired: 1,
      cert_misconfig: 2,
      missing_pfs: 9,
      weak_key: 1,
      insecure_sig_alg: 1,
      insecure_starttls: 18,
    },
    sessions: sessions,
    tls_handshakes: tlsHandshakes,
    certificates: certificates,
    findings: findings,
    anomalies: anomalies,
    timeline: timeline,
    risk_assessment: {
      overall_risk_score: 29,
      posture_rating: 'Moderate',
      cryptographic_risk: 65,
      certificate_risk: 70,
      protocol_risk: 50,
      tls_anomaly_risk: 55,
      configuration_risk: 60,
      feature_contributions: [
        { feature_name: 'TLS Version & Protocol Deprecation', contribution_points: 25, description: 'Penalties for deprecated TLS 1.0/1.1 protocols or missing TLS 1.3.', category: 'Protocol' },
        { feature_name: 'Cipher Suite Strength & Modern AEAD', contribution_points: 20, description: 'Penalties for 3DES, RC4, or lack of GCM/Poly1305 authentication.', category: 'Cryptography' },
        { feature_name: 'Certificate Validity & PKI Assurance', contribution_points: 15, description: 'Penalties for expired certificates and self-signed chains.', category: 'Certificates' },
        { feature_name: 'Key Exchange & Forward Secrecy', contribution_points: 10, description: 'Penalties for static RSA key exchange without ephemeral Diffie-Hellman.', category: 'Key Exchange' },
        { feature_name: 'STARTTLS Transition Integrity', contribution_points: 10, description: 'Penalties for unencrypted plaintext streams or STARTTLS downgrade events.', category: 'STARTTLS' },
        { feature_name: 'Heuristic Protocol Anomaly Index', contribution_points: 12, description: 'Statistical weights for unusual handshake latency and auth leaks.', category: 'Anomalies' },
      ],
      top_risk_drivers: [
        'Expired or Self-Signed X.509 certificates present in active sessions',
        'Legacy TLS 1.0/1.1 protocol negotiation observed',
        'Weak 64-bit 3DES / RC4 cipher suites active on mail ports',
      ],
      model_version: 'Sentinel-RiskEngine-v2.4 (Explainable ML Rule Hybrid)',
    },
    threat_matrix: [
      { finding_id: 'CRYPTO-001', title: 'Deprecated TLS 1.0 Negotiation', severity: 'HIGH', impact_score: 4, likelihood_score: 4, exploitability: 'HIGH', exposure: 'EXTERNAL', affected_sessions_count: 3, confidence: 'HIGH' },
      { finding_id: 'CRYPTO-002', title: 'Weak 64-bit 3DES Block Cipher', severity: 'HIGH', impact_score: 4, likelihood_score: 3, exploitability: 'MEDIUM', exposure: 'EXTERNAL', affected_sessions_count: 2, confidence: 'HIGH' },
      { finding_id: 'CRYPTO-003', title: 'Expired X.509 Certificate', severity: 'CRITICAL', impact_score: 5, likelihood_score: 5, exploitability: 'HIGH', exposure: 'EXTERNAL', affected_sessions_count: 1, confidence: 'HIGH' },
      { finding_id: 'CRYPTO-004', title: 'Prohibited RC4 Stream Cipher', severity: 'CRITICAL', impact_score: 5, likelihood_score: 4, exploitability: 'HIGH', exposure: 'EXTERNAL', affected_sessions_count: 1, confidence: 'HIGH' },
      { finding_id: 'CRYPTO-005', title: 'Untrusted Self-Signed Certificate', severity: 'HIGH', impact_score: 4, likelihood_score: 3, exploitability: 'MEDIUM', exposure: 'INTERNAL', affected_sessions_count: 1, confidence: 'HIGH' },
      { finding_id: 'CRYPTO-006', title: 'STARTTLS Stripping Downgrade', severity: 'CRITICAL', impact_score: 5, likelihood_score: 4, exploitability: 'HIGH', exposure: 'EXTERNAL', affected_sessions_count: 1, confidence: 'HIGH' },
      { finding_id: 'CRYPTO-007', title: 'Missing Perfect Forward Secrecy', severity: 'MEDIUM', impact_score: 3, likelihood_score: 3, exploitability: 'MEDIUM', exposure: 'INTERNAL', affected_sessions_count: 9, confidence: 'HIGH' },
    ],
    security_posture: {
      overall_score: 71,
      previous_score: 64,
      change: 7,
      breakdown: {
        protocol_security: 85,
        tls_configuration: 78,
        certificate_security: 80,
        cryptographic_strength: 75,
        forward_secrecy: 90,
        starttls_security: 82,
        configuration_hygiene: 88,
      },
      top_recommended_actions: [
        { priority: 1, title: 'Disable Deprecated TLS 1.0 & TLS 1.1', action: 'Configure mail server ssl_protocols TLSv1.2 TLSv1.3 across all SMTP/IMAP listeners.', effort: 'LOW', impact: 'HIGH' },
        { priority: 2, title: 'Replace Weak Cipher Suites (3DES/RC4)', action: 'Enforce modern AEAD ciphers with ECDHE key exchange and remove all CBC/3DES ciphers.', effort: 'LOW', impact: 'HIGH' },
        { priority: 3, title: 'Renew & Replace Expired/Self-Signed Certificates', action: 'Deploy automated ACME certificate management (Let\'s Encrypt / DigiCert PKI) for all mail domains.', effort: 'MEDIUM', impact: 'CRITICAL' },
        { priority: 4, title: 'Enforce Mandatory STARTTLS & MTA-STS Policy', action: 'Publish RFC 8461 _mta-sts TXT record and enforce TLS requirements on incoming port 25/587.', effort: 'MEDIUM', impact: 'HIGH' },
        { priority: 5, title: 'Enable Perfect Forward Secrecy (PFS)', action: 'Ensure ECDHE curves X25519 and P-256 are prioritized for all inbound and outbound email handshakes.', effort: 'LOW', impact: 'MEDIUM' },
      ],
    },
  };
}
