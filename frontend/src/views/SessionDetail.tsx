import React, { useState } from 'react';
import {
  ArrowLeft,
  Lock,
  Unlock,
  ShieldAlert,
  AlertTriangle,
  Clock,
  HardDrive,
  Radio,
  Server,
  Terminal,
  CheckCircle2,
  FileCode,
  ShieldCheck,
  Zap,
  ArrowRight
} from 'lucide-react';
import { EmailSession, PCAPAnalysis } from '../types';

interface SessionDetailProps {
  session: EmailSession;
  analysis: PCAPAnalysis;
  onBack: () => void;
  onNavigateTab: (tab: any) => void;
}

export const SessionDetail: React.FC<SessionDetailProps> = ({
  session,
  analysis,
  onBack,
  onNavigateTab
}) => {
  const [activeTab, setActiveTab] = useState<'flow' | 'crypto' | 'raw'>('flow');

  // Match corresponding certificate and TLS details
  const cert = analysis.certificates.find((c) => c.session_id === session.session_id || c.id === session.certificate_id);
  const tls = analysis.tls_handshakes.find((t) => t.session_id === session.session_id);
  const sessionFindings = analysis.findings.filter((f) => f.session_id === session.session_id);

  return (
    <div className="space-y-6 pb-12">
      {/* Top Header & Navigation */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#0d1424] border border-slate-800 rounded-lg p-4">
        <div className="flex items-center space-x-3">
          <button
            onClick={onBack}
            className="p-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
            title="Back to Sessions Table"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-bold text-white font-mono">{session.session_id}</span>
              <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 font-bold text-[10px]">
                {session.protocol}
              </span>
              <span
                className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                  session.status === 'ENCRYPTED'
                    ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                    : session.status === 'DOWNGRADED'
                    ? 'bg-red-950 text-red-400 border-red-800'
                    : 'bg-amber-950 text-amber-400 border-amber-800'
                }`}
              >
                {session.status}
              </span>
            </div>
            <div className="text-[11px] text-slate-400 mt-0.5">
              Flow: <span className="text-slate-200 font-mono">{session.source_ip}:{session.source_port}</span> &rarr;{' '}
              <span className="text-slate-200 font-mono">{session.dest_ip}:{session.dest_port}</span>
            </div>
          </div>
        </div>

        {/* Action badges */}
        <div className="flex items-center space-x-2">
          <div className="text-right text-xs">
            <div className="text-slate-400">Risk Assessment</div>
            <div className={`font-bold font-mono ${session.risk === 'CRITICAL' ? 'text-red-400' : (session.risk === 'HIGH' ? 'text-orange-400' : 'text-emerald-400')}`}>
              {session.risk} ({session.risk_score}/100)
            </div>
          </div>
        </div>
      </div>

      {/* Session Metadata KPI Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-3">
          <div className="text-slate-400 text-[10px] uppercase font-bold">Duration</div>
          <div className="text-sm font-mono font-bold text-white mt-1">{session.duration_ms} ms</div>
        </div>
        <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-3">
          <div className="text-slate-400 text-[10px] uppercase font-bold">Packets / Bytes</div>
          <div className="text-sm font-mono font-bold text-white mt-1">{session.packet_count} / {(session.byte_count / 1024).toFixed(1)} KB</div>
        </div>
        <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-3">
          <div className="text-slate-400 text-[10px] uppercase font-bold">STARTTLS Command</div>
          <div className={`text-sm font-bold mt-1 ${session.starttls_requested ? 'text-emerald-400' : 'text-slate-400'}`}>
            {session.starttls_requested ? 'REQUESTED (YES)' : 'NOT REQUESTED'}
          </div>
        </div>
        <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-3">
          <div className="text-slate-400 text-[10px] uppercase font-bold">TLS Version</div>
          <div className="text-sm font-bold text-cyan-300 mt-1">{session.tls_version || 'None (Plaintext)'}</div>
        </div>
        <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-3">
          <div className="text-slate-400 text-[10px] uppercase font-bold">Cipher Suite</div>
          <div className="text-xs font-mono text-slate-200 mt-1 truncate" title={session.cipher_suite || 'N/A'}>
            {session.cipher_suite || 'None'}
          </div>
        </div>
        <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-3">
          <div className="text-slate-400 text-[10px] uppercase font-bold">Cert Chain</div>
          <div className="text-xs font-bold text-purple-400 mt-1 truncate">
            {cert ? cert.chain_status : 'N/A'}
          </div>
        </div>
      </div>

      {/* Forensic Warnings & Risk Explanation */}
      {session.explainable_risk_factors.length > 0 && (
        <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-4">
          <div className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-2 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-amber-400" />
            Explainable AI Risk Factors & Forensic Indicators
          </div>
          <div className="flex flex-wrap gap-2">
            {session.explainable_risk_factors.map((factor, idx) => (
              <span
                key={idx}
                className="text-xs px-2.5 py-1 rounded bg-[#090e1a] border border-slate-700 text-amber-300 font-mono"
              >
                {factor}
              </span>
            ))}
            {session.flags.map((flag, idx) => (
              <span
                key={`f-${idx}`}
                className="text-xs px-2.5 py-1 rounded bg-slate-800 border border-slate-700 text-slate-300 font-sans"
              >
                {flag}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Forensic Inspection Tabs */}
      <div className="flex space-x-2 border-b border-slate-800">
        {[
          { id: 'flow', label: 'Communication Flow (Ladder Diagram)', icon: Zap },
          { id: 'crypto', label: 'Cryptographic & TLS Details', icon: Lock },
          { id: 'raw', label: 'Technical Evidence & Findings', icon: Terminal },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`px-4 py-2.5 text-xs font-semibold flex items-center gap-2 border-b-2 transition-all ${
                isActive
                  ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Tab 1: Communication Flow Visualization */}
      {activeTab === 'flow' && (
        <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-6">
          <div className="flex items-center justify-between mb-6 pb-3 border-b border-slate-800">
            <div>
              <div className="text-xs font-bold uppercase tracking-wider text-slate-200">
                Bidirectional TCP & Protocol State Transition
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                Reconstructed packet-by-packet sequence highlighting transitions from plaintext banner greetings to TLS handshake and encrypted email payload.
              </div>
            </div>
            <div className="flex items-center gap-4 text-xs font-mono">
              <span className="flex items-center gap-1.5 text-amber-400">
                <Unlock className="w-3.5 h-3.5" /> Plaintext Phase
              </span>
              <span className="flex items-center gap-1.5 text-emerald-400">
                <Lock className="w-3.5 h-3.5" /> Encrypted Phase
              </span>
            </div>
          </div>

          {/* Ladder Diagram Layout */}
          <div className="space-y-4 relative before:absolute before:inset-0 before:left-1/2 before:-translate-x-1/2 before:w-0.5 before:bg-slate-800">
            {session.communication_flow && session.communication_flow.length > 0 ? (
              session.communication_flow.map((step) => {
                const isClient = step.sender === 'Client';
                const isEncrypted = step.is_encrypted;

                return (
                  <div
                    key={step.step_number}
                    className={`flex items-start gap-4 relative z-10 ${
                      isClient ? 'flex-row' : 'flex-row-reverse'
                    }`}
                  >
                    {/* Flow bubble card */}
                    <div
                      className={`w-5/12 p-3.5 rounded-lg border text-xs ${
                        isEncrypted
                          ? 'bg-[#08151f] border-emerald-600/50 shadow-lg shadow-emerald-950/20'
                          : 'bg-[#090e1a] border-slate-800'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1 text-[10px]">
                        <span className="font-bold text-slate-400 uppercase tracking-wider">
                          {step.sender} &bull; {step.protocol_layer}
                        </span>
                        <span className="font-mono text-slate-400">+{step.timestamp_offset_ms}ms</span>
                      </div>

                      <div className={`font-mono text-xs font-bold ${isEncrypted ? 'text-emerald-300' : 'text-cyan-300'}`}>
                        {step.command_or_status}
                      </div>

                      <div className="text-[11px] text-slate-400 mt-1 leading-snug">
                        {step.description}
                      </div>

                      {step.raw_payload_snippet && (
                        <div className="mt-2 p-2 rounded bg-black/50 border border-slate-800/80 font-mono text-[10px] text-slate-400 overflow-x-auto">
                          {step.raw_payload_snippet}
                        </div>
                      )}
                    </div>

                    {/* Step Number Badge in center */}
                    <div
                      className={`w-7 h-7 rounded-full flex items-center justify-center text-[10px] font-bold font-mono border z-20 shrink-0 ${
                        isEncrypted
                          ? 'bg-emerald-950 text-emerald-300 border-emerald-500'
                          : 'bg-[#0f172a] text-cyan-300 border-cyan-800'
                      }`}
                    >
                      {step.step_number}
                    </div>

                    {/* Empty spacer for the other half */}
                    <div className="w-5/12"></div>
                  </div>
                );
              })
            ) : (
              <div className="text-center py-8 text-xs text-slate-400">
                No step-by-step ladder flow available for this session.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 2: Cryptographic & TLS Details */}
      {activeTab === 'crypto' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* TLS Handshake Details */}
          <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-5 space-y-4">
            <div className="text-xs font-bold uppercase tracking-wider text-slate-200 pb-2 border-b border-slate-800 flex justify-between items-center">
              <span>TLS Handshake Parameters</span>
              <span className="text-[10px] text-cyan-400 font-mono">{tls?.tls_version || 'N/A'}</span>
            </div>

            {tls ? (
              <div className="space-y-3 text-xs">
                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">TLS Version</span>
                  <span className="font-mono font-bold text-slate-200">{tls.tls_version}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">Cipher Suite</span>
                  <span className="font-mono font-bold text-cyan-300 truncate max-w-[240px]" title={tls.cipher_suite}>{tls.cipher_suite}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">Key Exchange (KEX)</span>
                  <span className="font-mono font-bold text-slate-200">{tls.key_exchange}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">Perfect Forward Secrecy (PFS)</span>
                  <span className={`font-mono font-bold ${tls.forward_secrecy ? 'text-emerald-400' : 'text-red-400'}`}>
                    {tls.forward_secrecy ? 'ENABLED (YES)' : 'DISABLED (NO - Static RSA)'}
                  </span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">Authentication / Signature</span>
                  <span className="font-mono font-bold text-slate-200">{tls.authentication}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">Encryption Algorithm</span>
                  <span className="font-mono font-bold text-slate-200">{tls.encryption_algorithm}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">MAC / Hash Integrity</span>
                  <span className="font-mono font-bold text-slate-200">{tls.mac_hash}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">ALPN Protocol</span>
                  <span className="font-mono font-bold text-slate-200">{tls.alpn || 'None'}</span>
                </div>

                {tls.warnings.length > 0 && (
                  <div className="mt-4 p-3 rounded bg-red-950/40 border border-red-800/60">
                    <div className="text-[11px] font-bold text-red-400 flex items-center gap-1.5 mb-1">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      Cryptographic Weakness Warnings:
                    </div>
                    <ul className="list-disc pl-4 space-y-1 text-[11px] text-red-300">
                      {tls.warnings.map((w, i) => (
                        <li key={i}>{w}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-xs text-slate-400 py-6 text-center">
                This session did not establish a TLS handshake.
              </div>
            )}
          </div>

          {/* Certificate Inspection Details */}
          <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-5 space-y-4">
            <div className="text-xs font-bold uppercase tracking-wider text-slate-200 pb-2 border-b border-slate-800 flex justify-between items-center">
              <span>Presented X.509 Certificate</span>
              {cert && (
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                  cert.is_expired ? 'bg-red-950 text-red-400 border-red-800' : 'bg-emerald-950 text-emerald-400 border-emerald-800'
                }`}>
                  {cert.is_expired ? 'EXPIRED' : 'VALID'}
                </span>
              )}
            </div>

            {cert ? (
              <div className="space-y-3 text-xs">
                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">Subject CN</span>
                  <span className="font-mono font-bold text-slate-200">{cert.subject_cn}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">Issuer CA</span>
                  <span className="font-mono font-bold text-slate-200 truncate max-w-[240px]">{cert.issuer_cn}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">Public Key</span>
                  <span className={`font-mono font-bold ${cert.key_length < 2048 ? 'text-red-400' : 'text-slate-200'}`}>
                    {cert.public_key_algorithm} {cert.key_length} bits
                  </span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">Signature Algorithm</span>
                  <span className={`font-mono font-bold ${cert.signature_algorithm.includes('sha1') || cert.signature_algorithm.includes('md5') ? 'text-red-400' : 'text-slate-200'}`}>
                    {cert.signature_algorithm}
                  </span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">Validity Window</span>
                  <span className="font-mono text-slate-300 text-[11px]">{cert.valid_from.substring(0, 10)} to {cert.valid_until.substring(0, 10)}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">Days Remaining</span>
                  <span className={`font-mono font-bold ${cert.days_remaining < 0 ? 'text-red-400' : (cert.days_remaining < 30 ? 'text-amber-400' : 'text-emerald-400')}`}>
                    {cert.days_remaining} days
                  </span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                  <span className="text-slate-400">Subject Alt Names (SAN)</span>
                  <span className="font-mono text-[11px] text-cyan-300 truncate max-w-[240px]">
                    {cert.san_list.join(', ')}
                  </span>
                </div>

                <div className="pt-2">
                  <button
                    onClick={() => onNavigateTab('certificates')}
                    className="w-full py-1.5 text-xs font-semibold text-cyan-400 hover:text-cyan-300 bg-slate-900 border border-slate-800 rounded transition-colors text-center"
                  >
                    View in Certificate Chain Explorer &rarr;
                  </button>
                </div>
              </div>
            ) : (
              <div className="text-xs text-slate-400 py-6 text-center">
                No X.509 certificate attached to this session.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 3: Technical Evidence & Findings */}
      {activeTab === 'raw' && (
        <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-5 space-y-4">
          <div className="text-xs font-bold uppercase tracking-wider text-slate-200 pb-2 border-b border-slate-800">
            Forensic Findings Associated with Session {session.session_id}
          </div>

          {sessionFindings.length > 0 ? (
            <div className="space-y-3">
              {sessionFindings.map((finding) => (
                <div
                  key={finding.id}
                  className="p-4 rounded-lg bg-[#090e1a] border border-slate-800 hover:border-slate-700 transition-all space-y-2 text-xs"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-cyan-400">{finding.id}</span>
                      <span className="font-bold text-slate-100 text-sm">{finding.title}</span>
                    </div>
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                        finding.severity === 'CRITICAL'
                          ? 'bg-red-950 text-red-400 border-red-800'
                          : finding.severity === 'HIGH'
                          ? 'bg-orange-950 text-orange-400 border-orange-800'
                          : 'bg-amber-950 text-amber-400 border-amber-800'
                      }`}
                    >
                      {finding.severity}
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
                    <div className="p-2.5 rounded bg-black/40 border border-slate-800/80">
                      <div className="text-[10px] uppercase font-bold text-slate-400">Observed Evidence</div>
                      <div className="font-mono text-amber-300 mt-1">{finding.evidence_observed}</div>
                      <div className="text-[11px] text-slate-400 mt-1">{finding.evidence_detail}</div>
                    </div>
                    <div className="p-2.5 rounded bg-black/40 border border-slate-800/80">
                      <div className="text-[10px] uppercase font-bold text-slate-400">Recommended Secure State</div>
                      <div className="font-mono text-emerald-400 mt-1">{finding.expected_secure}</div>
                      <div className="text-[11px] text-slate-300 mt-1">{finding.recommendation}</div>
                    </div>
                  </div>

                  <div className="flex justify-between items-center text-[10px] text-slate-400 pt-1 font-mono">
                    <span>Packet/Stream Reference: {finding.packet_stream_ref}</span>
                    <span>CWE: {finding.cwe_id || 'CWE-326'} | CVSS: {finding.cvss_score || 7.5}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-8 text-center text-xs text-slate-400">
              No critical or high-risk findings detected for this session.
            </div>
          )}
        </div>
      )}
    </div>
  );
};
