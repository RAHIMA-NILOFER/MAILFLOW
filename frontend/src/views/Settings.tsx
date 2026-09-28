import React, { useState } from 'react';
import {
  Settings as SettingsIcon,
  ShieldCheck,
  Server,
  Lock,
  Cpu,
  RefreshCw,
  CheckCircle2,
  Database,
  Radio,
  Sliders
} from 'lucide-react';
import { PCAPAnalysis } from '../types';

interface SettingsProps {
  analysis: PCAPAnalysis | null;
}

export const Settings: React.FC<SettingsProps> = ({ analysis }) => {
  const [minTLSVersion, setMinTLSVersion] = useState('TLS 1.2');
  const [alertOnExpired, setAlertOnExpired] = useState(true);
  const [alertOnNoPFS, setAlertOnNoPFS] = useState(true);
  const [mtaStsEnforcement, setMtaStsEnforcement] = useState(true);
  const [pcapBufferMb, setPcapBufferMb] = useState(128);

  return (
    <div className="space-y-6 max-w-4xl mx-auto pb-12">
      {/* Header Banner */}
      <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-5">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-lg bg-cyan-950/60 border border-cyan-800/50 text-cyan-400">
            <SettingsIcon className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white">Forensic Engine Configuration</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Customize passive inspection thresholds, cryptographic baseline compliance rules, and parser parameters.
            </p>
          </div>
        </div>
      </div>

      {/* Passive Analysis Guardrails Banner */}
      <div className="bg-[#091522] border border-cyan-800/40 rounded-lg p-4 flex items-start gap-3">
        <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
        <div className="text-xs">
          <div className="font-bold text-slate-200">Strict Passive Forensics Architecture Certified</div>
          <div className="text-slate-400 mt-1 leading-relaxed">
            MailFlow Sentinel processes PCAP files using non-intrusive stream reassembly. The engine never transmits packets, conducts network scans, alters payload streams, or participates in MITM traffic interception.
          </div>
        </div>
      </div>

      {/* Cryptographic Compliance Standards Configuration */}
      <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-5 space-y-4">
        <div className="text-xs font-bold uppercase tracking-wider text-slate-200 pb-2 border-b border-slate-800 flex items-center gap-2">
          <Lock className="w-4 h-4 text-cyan-400" />
          Cryptographic Policy Baseline Rules
        </div>

        <div className="space-y-4 text-xs">
          <div className="flex items-center justify-between py-2 border-b border-slate-800/60">
            <div>
              <div className="font-bold text-slate-200">Minimum Approved TLS Protocol Version</div>
              <div className="text-slate-400 text-[11px]">Flag any session negotiating a version below this standard (RFC 8996).</div>
            </div>
            <select
              value={minTLSVersion}
              onChange={(e) => setMinTLSVersion(e.target.value)}
              className="bg-[#080c16] border border-slate-700 rounded px-3 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
            >
              <option value="TLS 1.3">TLS 1.3 (Strict High-Assurance)</option>
              <option value="TLS 1.2">TLS 1.2 (Standard Enterprise Recommended)</option>
              <option value="TLS 1.1">TLS 1.1 (Permissive Legacy)</option>
            </select>
          </div>

          <div className="flex items-center justify-between py-2 border-b border-slate-800/60">
            <div>
              <div className="font-bold text-slate-200">Enforce Perfect Forward Secrecy (PFS) Warning</div>
              <div className="text-slate-400 text-[11px]">Flag sessions with static RSA key exchange lacking ephemeral Diffie-Hellman.</div>
            </div>
            <input
              type="checkbox"
              checked={alertOnNoPFS}
              onChange={(e) => setAlertOnNoPFS(e.target.checked)}
              className="w-4 h-4 accent-cyan-500 rounded"
            />
          </div>

          <div className="flex items-center justify-between py-2 border-b border-slate-800/60">
            <div>
              <div className="font-bold text-slate-200">X.509 Certificate Expiration Warning Threshold</div>
              <div className="text-slate-400 text-[11px]">Trigger Medium severity alert when certificate expiration is within 30 days.</div>
            </div>
            <input
              type="checkbox"
              checked={alertOnExpired}
              onChange={(e) => setAlertOnExpired(e.target.checked)}
              className="w-4 h-4 accent-cyan-500 rounded"
            />
          </div>

          <div className="flex items-center justify-between py-2">
            <div>
              <div className="font-bold text-slate-200">MTA-STS Downgrade Prevention Audit (RFC 8461)</div>
              <div className="text-slate-400 text-[11px]">Score STARTTLS error 454/500 cleartext fallbacks as Critical severity finding.</div>
            </div>
            <input
              type="checkbox"
              checked={mtaStsEnforcement}
              onChange={(e) => setMtaStsEnforcement(e.target.checked)}
              className="w-4 h-4 accent-cyan-500 rounded"
            />
          </div>
        </div>
      </div>

      {/* Engine & Runtime System Info */}
      <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-5 space-y-3">
        <div className="text-xs font-bold uppercase tracking-wider text-slate-200 pb-2 border-b border-slate-800 flex items-center gap-2">
          <Server className="w-4 h-4 text-cyan-400" />
          System & Engine Runtime Information
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
          <div className="p-3 bg-[#080c16] rounded border border-slate-800">
            <div className="text-slate-400 text-[10px] uppercase font-sans">Platform Version</div>
            <div className="font-bold text-cyan-300 mt-1">v2.4.0-Production</div>
          </div>
          <div className="p-3 bg-[#080c16] rounded border border-slate-800">
            <div className="text-slate-400 text-[10px] uppercase font-sans">Backend Core</div>
            <div className="font-bold text-emerald-400 mt-1">Python 3.13 / FastAPI</div>
          </div>
          <div className="p-3 bg-[#080c16] rounded border border-slate-800">
            <div className="text-slate-400 text-[10px] uppercase font-sans">PCAP Engine</div>
            <div className="font-bold text-slate-200 mt-1">Scapy Stream Dissector</div>
          </div>
          <div className="p-3 bg-[#080c16] rounded border border-slate-800">
            <div className="text-slate-400 text-[10px] uppercase font-sans">Crypto Library</div>
            <div className="font-bold text-slate-200 mt-1">cryptography.x509</div>
          </div>
        </div>
      </div>
    </div>
  );
};
