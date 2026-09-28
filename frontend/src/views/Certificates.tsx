import React, { useState } from 'react';
import {
  Award,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Key,
  Layers,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  ShieldCheck,
  Search,
  Filter
} from 'lucide-react';
import { Certificate, PCAPAnalysis } from '../types';

interface CertificatesProps {
  analysis: PCAPAnalysis;
  onNavigateSession?: (sessionId: string) => void;
}

export const Certificates: React.FC<CertificatesProps> = ({ analysis }) => {
  const [selectedCert, setSelectedCert] = useState<Certificate>(
    analysis.certificates[0] || null
  );
  const [searchTerm, setSearchTerm] = useState('');

  const filteredCerts = analysis.certificates.filter((cert) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      cert.subject_cn.toLowerCase().includes(term) ||
      cert.issuer_cn.toLowerCase().includes(term) ||
      cert.id.toLowerCase().includes(term) ||
      cert.san_list.some((s) => s.toLowerCase().includes(term))
    );
  });

  return (
    <div className="space-y-6 pb-12">
      {/* Top Banner Header */}
      <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-full bg-cyan-950 text-cyan-300 text-[11px] font-semibold mb-2 border border-cyan-800/40">
              <Award className="w-3.5 h-3.5" />
              X.509 Certificate Chain & PKI Trust Inspector
            </div>
            <h2 className="text-xl font-bold text-white">X.509 Forensic Certificate Analysis</h2>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
              Passive extraction and validation of TLS certificate hierarchies, cryptographic key strengths (RSA/ECDSA), signature hashing algorithms, expiration timelines, and SAN coverage.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs font-mono px-3 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300">
              Total Certificates: <strong className="text-cyan-400">{analysis.total_certificates}</strong>
            </span>
          </div>
        </div>
      </div>

      {/* Main 2-Column Layout: Left Cert List, Right Detailed Cert Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Certificate Selector Cards */}
        <div className="lg:col-span-5 space-y-3">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search certificates by Subject, Issuer, or SAN..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-[#0d1424] border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-200 placeholder:text-slate-400 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <div className="space-y-2.5">
            {filteredCerts.map((cert) => {
              const isSelected = selectedCert?.id === cert.id;
              return (
                <div
                  key={cert.id}
                  onClick={() => setSelectedCert(cert)}
                  className={`p-4 rounded-lg border cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-cyan-950/30 border-cyan-500/70 shadow-lg shadow-cyan-950/40'
                      : 'bg-[#0d1424] border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-mono text-xs font-bold text-cyan-300">
                      {cert.id} &bull; {cert.session_id}
                    </span>
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                        cert.risk === 'CRITICAL'
                          ? 'bg-red-950 text-red-400 border-red-800'
                          : cert.risk === 'HIGH'
                          ? 'bg-orange-950 text-orange-400 border-orange-800'
                          : cert.risk === 'MEDIUM'
                          ? 'bg-amber-950 text-amber-400 border-amber-800'
                          : 'bg-emerald-950 text-emerald-400 border-emerald-800'
                      }`}
                    >
                      {cert.risk}
                    </span>
                  </div>

                  <div className="text-xs font-bold text-white truncate font-mono">
                    {cert.subject_cn}
                  </div>

                  <div className="text-[11px] text-slate-400 mt-1 truncate">
                    Issuer: {cert.issuer_cn}
                  </div>

                  <div className="flex items-center justify-between text-[10px] text-slate-400 mt-3 pt-2 border-t border-slate-800/80 font-mono">
                    <span>{cert.public_key_algorithm} {cert.key_length}b</span>
                    <span className={cert.is_expired ? 'text-red-400 font-bold' : (cert.is_expiring_soon ? 'text-amber-400 font-bold' : 'text-emerald-400')}>
                      {cert.days_remaining < 0 ? 'EXPIRED' : `${cert.days_remaining}d left`}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Deep Certificate Inspector */}
        {selectedCert ? (
          <div className="lg:col-span-7 space-y-4">
            {/* Header Box */}
            <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-5">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div>
                  <div className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                    Subject Common Name (CN)
                  </div>
                  <div className="text-base font-extrabold font-mono text-white mt-0.5">
                    {selectedCert.subject_cn}
                  </div>
                </div>
                <div className="text-right font-mono text-xs">
                  <div className="text-slate-400 text-[10px]">Session Ref</div>
                  <div className="font-bold text-cyan-300">{selectedCert.session_id}</div>
                </div>
              </div>

              {/* Certificate Chain Visualization (Root CA -> Intermediate CA -> Server Cert) */}
              <div className="mt-4 pt-1">
                <div className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-3 flex items-center gap-1.5">
                  <Layers className="w-3.5 h-3.5 text-cyan-400" />
                  Certificate Trust Chain Hierarchy
                </div>

                <div className="space-y-2 bg-[#080c16] p-4 rounded-lg border border-slate-800">
                  {selectedCert.chain_visualization.map((node, idx) => (
                    <div key={idx} className="flex items-center gap-3">
                      <div className="w-6 h-6 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-[10px] font-bold font-mono text-slate-300 shrink-0">
                        {idx + 1}
                      </div>
                      <div className="flex-1 p-2.5 rounded bg-[#0d1424] border border-slate-800 flex items-center justify-between text-xs">
                        <div>
                          <div className="text-[10px] uppercase font-bold text-slate-400">
                            {node.tier}
                          </div>
                          <div className="font-mono font-bold text-slate-200 mt-0.5">
                            {node.cn}
                          </div>
                        </div>
                        <span
                          className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                            node.status === 'TRUSTED' || node.status === 'VALID'
                              ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                              : 'bg-red-950 text-red-400 border-red-800'
                          }`}
                        >
                          {node.status}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* 8 Formal X.509 Validation Checks */}
            <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-5">
              <div className="text-xs font-bold uppercase tracking-wider text-slate-200 mb-3 pb-2 border-b border-slate-800">
                X.509 Cryptographic Validation Checklist
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                {[
                  { key: 'format_valid', label: 'Certificate ASN.1 Format' },
                  { key: 'validity_period', label: 'Active Validity Period Window' },
                  { key: 'hostname_san_match', label: 'Hostname / SAN Subject Match' },
                  { key: 'chain_completeness', label: 'PKI Chain Completeness' },
                  { key: 'signature_algorithm_strength', label: 'Signature Algorithm Strength' },
                  { key: 'public_key_strength', label: 'Public Key Bit Length (>=2048)' },
                  { key: 'unexpired', label: 'Unexpired Certificate Status' },
                  { key: 'trusted_root', label: 'Trusted Root CA Anchor' },
                ].map((check) => {
                  const passed = selectedCert.validation_checks[check.key] ?? true;
                  return (
                    <div
                      key={check.key}
                      className="p-2.5 rounded bg-[#090e1a] border border-slate-800/80 flex items-center justify-between"
                    >
                      <span className="text-slate-300">{check.label}</span>
                      {passed ? (
                        <span className="flex items-center gap-1 text-[11px] text-emerald-400 font-bold">
                          <CheckCircle2 className="w-3.5 h-3.5" /> PASS
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 text-[11px] text-red-400 font-bold">
                          <XCircle className="w-3.5 h-3.5" /> FAIL
                        </span>
                      )}
                    </div>
                  );
                })}
              </div>

              {/* Warning Callout Banners */}
              {selectedCert.warnings.length > 0 && (
                <div className="mt-4 p-3 rounded bg-red-950/40 border border-red-800 text-xs">
                  <div className="font-bold text-red-400 flex items-center gap-1.5 mb-1 text-[11px]">
                    <AlertTriangle className="w-3.5 h-3.5" /> Security Findings & Warnings:
                  </div>
                  <ul className="list-disc pl-4 space-y-1 text-red-300 text-[11px]">
                    {selectedCert.warnings.map((w, i) => (
                      <li key={i}>{w}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            {/* Technical Parameters Table */}
            <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-5 text-xs space-y-2 font-mono">
              <div className="text-xs font-bold uppercase tracking-wider text-slate-200 pb-2 border-b border-slate-800 font-sans">
                Technical Certificate Properties
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-800/50">
                <span className="text-slate-400 font-sans">Issuer Organization</span>
                <span className="text-slate-200 truncate max-w-[280px]">{selectedCert.issuer_cn}</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-800/50">
                <span className="text-slate-400 font-sans">Serial Number</span>
                <span className="text-cyan-300">{selectedCert.serial_number}</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-800/50">
                <span className="text-slate-400 font-sans">Public Key Algorithm</span>
                <span className="text-slate-200">{selectedCert.public_key_algorithm} ({selectedCert.key_length} bits)</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-800/50">
                <span className="text-slate-400 font-sans">Signature Algorithm</span>
                <span className="text-slate-200">{selectedCert.signature_algorithm}</span>
              </div>
              <div className="flex justify-between py-1.5 border-b border-slate-800/50">
                <span className="text-slate-400 font-sans">Subject Alternative Names (SAN)</span>
                <span className="text-cyan-300 truncate max-w-[280px]">{selectedCert.san_list.join(', ')}</span>
              </div>
              <div className="flex justify-between py-1.5">
                <span className="text-slate-400 font-sans">SHA-256 Fingerprint</span>
                <span className="text-slate-400 text-[10px] truncate max-w-[280px]" title={selectedCert.fingerprint_sha256}>
                  {selectedCert.fingerprint_sha256}
                </span>
              </div>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
};
