import React, { useState } from 'react';
import {
  Shield,
  Mail,
  Network,
  Lock,
  Brain,
  FileSearch,
  CheckCircle2,
  ChevronRight,
  ArrowRight,
  Sparkles,
  ShieldCheck,
  AlertTriangle
} from 'lucide-react';

interface LandingPageProps {
  onEnterDemo: () => void;
  onEnterLogin: () => void;
}

export const LandingPage: React.FC<LandingPageProps> = ({ onEnterDemo, onEnterLogin }) => {
  const [authMode, setAuthMode] = useState(false);
  const [operatorId, setOperatorId] = useState('SOC-ANALYST-09');
  const [accessKey, setAccessKey] = useState('••••••••••••');

  const handleLoginSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onEnterLogin();
  };

  return (
    <div className="min-h-screen bg-[#070a12] text-slate-100 flex flex-col justify-between selection:bg-cyan-500 selection:text-black">
      {/* Top Header */}
      <header className="border-b border-slate-800/80 bg-[#090e1a]/70 backdrop-blur-md px-8 py-4 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 via-blue-600 to-indigo-900 flex items-center justify-center shadow-lg shadow-cyan-900/40 border border-cyan-400/30">
            <Shield className="w-5 h-5 text-cyan-200" />
          </div>
          <div>
            <div className="font-extrabold text-base tracking-wider text-slate-100 flex items-center gap-1.5">
              MAILFLOW <span className="text-cyan-400">SENTINEL</span>
            </div>
            <div className="text-[10px] uppercase tracking-widest text-slate-400 font-semibold">
              Passive Email Cryptographic Forensics
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={() => setAuthMode(!authMode)}
            className="text-xs px-3.5 py-1.5 rounded-md border border-slate-700 bg-slate-800/80 text-slate-300 hover:text-white hover:bg-slate-800 transition-colors"
          >
            {authMode ? 'View Platform Overview' : 'Operator Sign In'}
          </button>
          <button
            onClick={onEnterDemo}
            className="text-xs px-4 py-1.5 rounded-md bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold shadow-md shadow-cyan-950/50 flex items-center gap-1.5 transition-all"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Enter Demo Analysis</span>
          </button>
        </div>
      </header>

      {/* Hero Section */}
      <main className="flex-1 max-w-6xl mx-auto w-full px-6 py-12 flex flex-col justify-center">
        {authMode ? (
          /* Operator Login Card */
          <div className="max-w-md mx-auto w-full bg-[#0d1424] border border-cyan-900/40 rounded-xl p-8 shadow-2xl shadow-cyan-950/50">
            <div className="text-center mb-6">
              <div className="w-14 h-14 mx-auto rounded-xl bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-inner mb-3">
                <Lock className="w-7 h-7" />
              </div>
              <h2 className="text-xl font-bold text-slate-100">SOC Operator Authentication</h2>
              <p className="text-xs text-slate-400 mt-1">
                Authenticate to access live passive forensic capture pipelines
              </p>
            </div>

            <form onSubmit={handleLoginSubmit} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1 uppercase tracking-wider text-[11px]">
                  Analyst ID / Call Sign
                </label>
                <input
                  type="text"
                  value={operatorId}
                  onChange={(e) => setOperatorId(e.target.value)}
                  className="w-full bg-[#080c16] border border-slate-700 rounded-md px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                  required
                />
              </div>
              <div>
                <label className="block text-slate-300 font-semibold mb-1 uppercase tracking-wider text-[11px]">
                  Certificate / Access Key
                </label>
                <input
                  type="password"
                  value={accessKey}
                  onChange={(e) => setAccessKey(e.target.value)}
                  className="w-full bg-[#080c16] border border-slate-700 rounded-md px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                  required
                />
              </div>

              <div className="pt-2">
                <button
                  type="submit"
                  className="w-full py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold rounded-md shadow-lg shadow-cyan-950/40 transition-all flex items-center justify-center gap-2 text-xs"
                >
                  <ShieldCheck className="w-4 h-4" />
                  <span>Access MailFlow SOC</span>
                </button>
              </div>

              <div className="text-center pt-2">
                <button
                  type="button"
                  onClick={onEnterDemo}
                  className="text-cyan-400 hover:underline text-[11px] font-medium"
                >
                  Skip login and enter Demo Workspace &rarr;
                </button>
              </div>
            </form>
          </div>
        ) : (
          /* Main Platform Landing / Showcase */
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
            <div className="lg:col-span-7 space-y-6">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/80 border border-cyan-500/40 text-cyan-300 text-xs font-semibold">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
                Passive Email Cryptographic Forensics & AI Risk Engine
              </div>

              <h1 className="text-4xl sm:text-5xl font-extrabold tracking-tight text-white leading-tight">
                Defensive Forensic Analysis for <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-sky-300 to-blue-500">SMTP, IMAP & POP3</span> Traffic.
              </h1>

              <p className="text-slate-400 text-sm sm:text-base leading-relaxed max-w-2xl">
                Reconstruct email communication streams from PCAP captures, inspect STARTTLS and TLS 1.3/1.2 handshakes, validate X.509 certificate chains, uncover cryptographic weaknesses, and generate explainable AI risk assessments.
              </p>

              {/* Action Buttons */}
              <div className="flex flex-wrap items-center gap-4 pt-2">
                <button
                  onClick={onEnterDemo}
                  className="px-6 py-3 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold shadow-xl shadow-cyan-950/60 flex items-center gap-2 text-sm transition-all transform hover:-translate-y-0.5"
                >
                  <Sparkles className="w-4 h-4" />
                  <span>Launch Demo Analysis</span>
                  <ChevronRight className="w-4 h-4" />
                </button>

                <button
                  onClick={() => setAuthMode(true)}
                  className="px-5 py-3 rounded-lg bg-slate-900/90 border border-slate-700 hover:border-slate-500 text-slate-200 font-semibold text-sm flex items-center gap-2 transition-all"
                >
                  <ShieldCheck className="w-4 h-4 text-cyan-400" />
                  <span>Sign In as SOC Operator</span>
                </button>
              </div>

              {/* Passive Guardrails Note */}
              <div className="p-3.5 rounded-lg bg-[#0c1220] border border-cyan-900/30 text-xs text-slate-400 flex items-start gap-3">
                <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <span className="font-semibold text-slate-200">Strict Passive Forensics Guarantee:</span> MailFlow Sentinel operates exclusively on recorded packet captures. Zero packet injection, no active network probing, and no traffic modification.
                </div>
              </div>
            </div>

            {/* Visual Right Column: Interactive Architecture Card */}
            <div className="lg:col-span-5 bg-[#0b101e] border border-slate-800/90 rounded-2xl p-6 shadow-2xl shadow-cyan-950/30 relative">
              <div className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-4 flex justify-between items-center">
                <span>Forensic Pipeline Architecture</span>
                <span className="text-[10px] bg-cyan-950 text-cyan-400 px-2 py-0.5 rounded font-mono">v2.4 Ready</span>
              </div>

              <div className="space-y-3">
                {[
                  { icon: FileSearch, title: 'PCAP & TCP Reassembly', desc: 'Passive stream reconstruction for ports 25, 587, 465, 143, 993, 110, 995', color: 'text-cyan-400' },
                  { icon: Lock, title: 'STARTTLS & TLS Inspection', desc: 'Cipher suite auditing, PFS validation, and downgrade detection (RFC 8996)', color: 'text-blue-400' },
                  { icon: Shield, title: 'X.509 Certificate Engine', desc: 'Chain validation, expiry countdowns, key length & signature algorithm checks', color: 'text-emerald-400' },
                  { icon: Brain, title: 'Explainable AI Risk Engine', desc: 'Transparent mathematical feature contribution scoring (0-100 Posture Score)', color: 'text-purple-400' }
                ].map((step, idx) => {
                  const Icon = step.icon;
                  return (
                    <div key={idx} className="p-3 rounded-lg bg-[#0f172a]/90 border border-slate-800 flex items-start gap-3">
                      <div className={`p-2 rounded bg-slate-900 border border-slate-800 ${step.color}`}>
                        <Icon className="w-4 h-4" />
                      </div>
                      <div>
                        <div className="text-xs font-bold text-slate-200">{step.title}</div>
                        <div className="text-[11px] text-slate-400 mt-0.5 leading-snug">{step.desc}</div>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Live Metric Preview */}
              <div className="mt-4 pt-4 border-t border-slate-800/80 grid grid-cols-3 gap-2 text-center">
                <div className="p-2 rounded bg-[#080c16]">
                  <div className="text-xs font-bold text-cyan-400">127</div>
                  <div className="text-[10px] text-slate-400">Demo Sessions</div>
                </div>
                <div className="p-2 rounded bg-[#080c16]">
                  <div className="text-xs font-bold text-emerald-400">71/100</div>
                  <div className="text-[10px] text-slate-400">Posture Score</div>
                </div>
                <div className="p-2 rounded bg-[#080c16]">
                  <div className="text-xs font-bold text-amber-400">3 Crit / 12 High</div>
                  <div className="text-[10px] text-slate-400">Findings</div>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-[#090e1a]/60 px-8 py-3 text-center text-xs text-slate-400 flex flex-col sm:flex-row justify-between items-center gap-2">
        <div>
          <strong>MAILFLOW SENTINEL</strong> &bull; Passive Email Cryptographic Forensics &bull; RFC 8461 / RFC 8996
        </div>
        <div className="text-[11px] text-slate-400">
          Built for Security Operations Centers (SOC) & Digital Forensics Teams
        </div>
      </footer>
    </div>
  );
};
