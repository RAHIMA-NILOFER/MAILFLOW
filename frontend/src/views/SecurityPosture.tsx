import React from 'react';
import {
  ShieldCheck,
  TrendingUp,
  ArrowUpRight,
  CheckCircle2,
  AlertTriangle,
  Zap,
  Layers,
  Sparkles,
  ListOrdered
} from 'lucide-react';
import { PCAPAnalysis } from '../types';

interface SecurityPostureProps {
  analysis: PCAPAnalysis;
  onNavigateTab: (tab: any) => void;
}

export const SecurityPosture: React.FC<SecurityPostureProps> = ({ analysis, onNavigateTab }) => {
  const posture = analysis.security_posture;
  const currentScore = posture?.overall_score || analysis.security_score || 71;
  const prevScore = posture?.previous_score || 64;
  const change = posture?.change || 7;

  const breakdown = posture?.breakdown || {
    protocol_security: 85,
    tls_configuration: 78,
    certificate_security: 80,
    cryptographic_strength: 75,
    forward_secrecy: 90,
    starttls_security: 82,
    configuration_hygiene: 88,
  };

  const actions = posture?.top_recommended_actions || [
    { priority: 1, title: 'Disable Deprecated TLS 1.0 & TLS 1.1', action: 'Configure mail server ssl_protocols TLSv1.2 TLSv1.3 across all SMTP/IMAP listeners.', effort: 'LOW', impact: 'HIGH' },
    { priority: 2, title: 'Replace Weak Cipher Suites (3DES/RC4)', action: 'Enforce modern AEAD ciphers with ECDHE key exchange and remove all CBC/3DES ciphers.', effort: 'LOW', impact: 'HIGH' },
    { priority: 3, title: 'Renew & Replace Expired/Self-Signed Certificates', action: 'Deploy automated ACME certificate management (Let\'s Encrypt / DigiCert PKI) for all mail domains.', effort: 'MEDIUM', impact: 'CRITICAL' },
    { priority: 4, title: 'Enforce Mandatory STARTTLS & MTA-STS Policy', action: 'Publish RFC 8461 _mta-sts TXT record and enforce TLS requirements on incoming port 25/587.', effort: 'MEDIUM', impact: 'HIGH' },
    { priority: 5, title: 'Enable Perfect Forward Secrecy (PFS)', action: 'Ensure ECDHE curves X25519 and P-256 are prioritized for all inbound and outbound email handshakes.', effort: 'LOW', impact: 'MEDIUM' },
  ];

  return (
    <div className="space-y-6 pb-12">
      {/* Top Banner Header */}
      <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-full bg-cyan-950 text-cyan-300 text-[11px] font-semibold mb-2 border border-cyan-800/40">
              <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
              Cryptographic Posture & Compliance Dashboard
            </div>
            <h2 className="text-xl font-bold text-white">Enterprise Security Posture</h2>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
              Consolidated security posture index evaluated against RFC 8996, RFC 8461 (MTA-STS), and NIST SP 800-52r2 cryptographic guidelines.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <div className="p-3 rounded-lg bg-[#080c16] border border-slate-800 text-center">
              <div className="text-[10px] text-slate-400">Previous Score</div>
              <div className="text-sm font-mono font-bold text-slate-300">{prevScore}/100</div>
            </div>
            <div className="p-3 rounded-lg bg-[#080c16] border border-slate-800 text-center">
              <div className="text-[10px] text-slate-400">Posture Delta</div>
              <div className="text-sm font-mono font-bold text-emerald-400 flex items-center justify-center gap-0.5">
                <TrendingUp className="w-3.5 h-3.5" /> +{change}%
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Main Score Gauge + 7-Category Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Main Circular Score Gauge */}
        <div className="lg:col-span-4 bg-[#0d1424] border border-slate-800 rounded-lg p-6 flex flex-col justify-between items-center text-center">
          <div className="w-full text-xs font-bold uppercase tracking-wider text-slate-300 text-left pb-2 border-b border-slate-800">
            Current Cryptographic Score
          </div>

          <div className="my-8 relative w-44 h-44 flex items-center justify-center">
            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
              <path
                className="text-slate-800"
                strokeWidth="3.2"
                stroke="currentColor"
                fill="none"
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              />
              <path
                className="text-cyan-400"
                strokeDasharray={`${currentScore}, 100`}
                strokeWidth="3.2"
                strokeLinecap="round"
                stroke="currentColor"
                fill="none"
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              />
            </svg>
            <div className="absolute text-center">
              <div className="text-4xl font-extrabold font-mono text-white">{currentScore}</div>
              <div className="text-[10px] uppercase tracking-wider text-slate-400 font-bold -mt-1">/ 100 Total</div>
            </div>
          </div>

          <div className="w-full p-3 rounded bg-[#080c16] border border-slate-800 text-xs text-left space-y-1">
            <div className="text-slate-400 text-[10px] uppercase font-bold">Posture Classification:</div>
            <div className="font-bold text-cyan-300 text-sm">
              {currentScore >= 80 ? 'EXCELLENT COMPLIANCE' : (currentScore >= 60 ? 'ACCEPTABLE / MODERATE' : 'CRITICAL DEFICIENCIES')}
            </div>
          </div>
        </div>

        {/* 7 Breakdown Categories */}
        <div className="lg:col-span-8 bg-[#0d1424] border border-slate-800 rounded-lg p-6 flex flex-col justify-between">
          <div className="text-xs font-bold uppercase tracking-wider text-slate-200 mb-4 pb-2 border-b border-slate-800">
            7-Pillar Security Posture Breakdown
          </div>

          <div className="space-y-4">
            {[
              { key: 'protocol_security', label: 'Protocol Security', desc: 'Port hardening, implicit TLS coverage & protocol isolation' },
              { key: 'tls_configuration', label: 'TLS Configuration', desc: 'RFC 8996 compliance, disabled SSL/TLS 1.0/1.1' },
              { key: 'certificate_security', label: 'Certificate Security', desc: 'X.509 validity windows, trusted roots, automated renewal' },
              { key: 'cryptographic_strength', label: 'Cryptographic Strength', desc: 'Prohibition of 64-bit ciphers (3DES) and broken RC4' },
              { key: 'forward_secrecy', label: 'Forward Secrecy (PFS)', desc: 'Ephemeral ECDHE key exchange enforcement' },
              { key: 'starttls_security', label: 'STARTTLS Security', desc: 'Downgrade prevention, mandatory TLS policy' },
              { key: 'configuration_hygiene', label: 'Configuration Hygiene', desc: 'MTA-STS TXT records and DANE TLSA anchoring' },
            ].map((pillar) => {
              const score = (breakdown as any)[pillar.key] || 75;
              const barColor = score >= 80 ? 'from-cyan-500 to-emerald-400' : (score >= 65 ? 'from-cyan-500 to-amber-400' : 'from-orange-500 to-red-500');

              return (
                <div key={pillar.key} className="space-y-1">
                  <div className="flex justify-between items-center text-xs">
                    <span className="font-bold text-slate-200">{pillar.label}</span>
                    <span className="font-mono font-bold text-slate-300">{score}/100</span>
                  </div>
                  <div className="w-full h-2 rounded-full bg-slate-800 overflow-hidden">
                    <div
                      className={`h-full bg-gradient-to-r ${barColor} rounded-full transition-all duration-500`}
                      style={{ width: `${score}%` }}
                    ></div>
                  </div>
                  <div className="text-[10px] text-slate-400">{pillar.desc}</div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Top 5 Recommended Actions */}
      <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-6">
        <div className="text-xs font-bold uppercase tracking-wider text-slate-200 mb-4 pb-2 border-b border-slate-800 flex items-center gap-2">
          <ListOrdered className="w-4 h-4 text-cyan-400" />
          Top Actionable Security Recommendations (Prioritized)
        </div>

        <div className="space-y-3">
          {actions.map((act) => (
            <div
              key={act.priority}
              className="p-4 rounded-lg bg-[#080c16] border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
            >
              <div className="flex items-start gap-3">
                <div className="w-6 h-6 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/60 font-mono font-bold flex items-center justify-center shrink-0">
                  {act.priority}
                </div>
                <div>
                  <div className="font-bold text-slate-100 text-sm">{act.title}</div>
                  <div className="text-slate-400 text-xs mt-0.5 leading-relaxed">{act.action}</div>
                </div>
              </div>

              <div className="flex items-center gap-2 font-mono text-[10px] shrink-0">
                <span className="px-2 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300">
                  Effort: <strong className="text-cyan-300">{act.effort}</strong>
                </span>
                <span className="px-2 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300">
                  Impact: <strong className="text-emerald-400">{act.impact}</strong>
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
