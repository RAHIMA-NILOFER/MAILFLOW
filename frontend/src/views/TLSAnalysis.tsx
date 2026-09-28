import React, { useState } from 'react';
import {
  Lock,
  Unlock,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Cpu,
  Layers,
  Search,
  Filter
} from 'lucide-react';
import { PCAPAnalysis, TLSHandshake } from '../types';

interface TLSAnalysisProps {
  analysis: PCAPAnalysis;
  onNavigateSession?: (sessionId: string) => void;
}

export const TLSAnalysis: React.FC<TLSAnalysisProps> = ({ analysis, onNavigateSession }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [versionFilter, setVersionFilter] = useState('ALL');
  const [pfsFilter, setPfsFilter] = useState('ALL');

  const filteredTLS = analysis.tls_handshakes.filter((tls) => {
    if (versionFilter !== 'ALL' && tls.tls_version !== versionFilter) return false;
    if (pfsFilter === 'YES' && !tls.forward_secrecy) return false;
    if (pfsFilter === 'NO' && tls.forward_secrecy) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      const matchId = tls.session_id.toLowerCase().includes(term);
      const matchCipher = tls.cipher_suite.toLowerCase().includes(term);
      const matchSni = tls.sni_server_name?.toLowerCase().includes(term);
      if (!matchId && !matchCipher && !matchSni) return false;
    }
    return true;
  });

  return (
    <div className="space-y-6 pb-12">
      {/* Top Banner Overview */}
      <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-full bg-cyan-950 text-cyan-300 text-[11px] font-semibold mb-2 border border-cyan-800/40">
              <Lock className="w-3.5 h-3.5" />
              Cryptographic Protocol & Cipher Suite Inspector
            </div>
            <h2 className="text-xl font-bold text-white">TLS Handshake Forensic Analysis</h2>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
              Passive auditing of negotiated TLS versions, key exchange parameters, Perfect Forward Secrecy (PFS) assurance, AEAD encryption modes, and deprecated cipher suites across all captured mail sessions.
            </p>
          </div>

          <div className="grid grid-cols-3 gap-2 text-center text-xs">
            <div className="p-2.5 rounded bg-[#090e1a] border border-slate-800">
              <div className="text-[10px] text-slate-400">TLS 1.3 Active</div>
              <div className="text-base font-bold font-mono text-emerald-400 mt-0.5">
                {analysis.tls_version_distribution.tls13}
              </div>
            </div>
            <div className="p-2.5 rounded bg-[#090e1a] border border-slate-800">
              <div className="text-[10px] text-slate-400">TLS 1.2 Active</div>
              <div className="text-base font-bold font-mono text-cyan-400 mt-0.5">
                {analysis.tls_version_distribution.tls12}
              </div>
            </div>
            <div className="p-2.5 rounded bg-[#090e1a] border border-slate-800">
              <div className="text-[10px] text-slate-400">Deprecated (1.0/1.1)</div>
              <div className="text-base font-bold font-mono text-red-400 mt-0.5">
                {analysis.tls_version_distribution.tls10 + analysis.tls_version_distribution.tls11}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Cryptographic Standards Compliance Callouts */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        <div className="bg-[#0d1424] border border-red-900/40 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-slate-300">TLS 1.0 & TLS 1.1</span>
            <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800">
              DEPRECATED
            </span>
          </div>
          <div className="text-xs text-slate-400 mt-2 leading-relaxed">
            Formally prohibited under RFC 8996 due to lack of modern AEAD ciphers and susceptibility to POODLE / BEAST attacks.
          </div>
        </div>

        <div className="bg-[#0d1424] border border-red-900/40 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-slate-300">3DES & RC4 Ciphers</span>
            <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800">
              CRITICAL WEAKNESS
            </span>
          </div>
          <div className="text-xs text-slate-400 mt-2 leading-relaxed">
            3DES 64-bit block collision vulnerability (Sweet32 / CVE-2016-2183) and broken RC4 single-byte biases (RFC 7465).
          </div>
        </div>

        <div className="bg-[#0d1424] border border-amber-900/40 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-slate-300">Static RSA Key Exchange</span>
            <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-amber-950 text-amber-400 border border-amber-800">
              NO FORWARD SECRECY
            </span>
          </div>
          <div className="text-xs text-slate-400 mt-2 leading-relaxed">
            Lack of ephemeral Diffie-Hellman allows retroactive PCAP decryption if server private key is ever exposed.
          </div>
        </div>

        <div className="bg-[#0d1424] border border-emerald-900/40 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-bold text-slate-300">TLS 1.3 Modern AEAD</span>
            <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
              RECOMMENDED
            </span>
          </div>
          <div className="text-xs text-slate-400 mt-2 leading-relaxed">
            Mandatory Perfect Forward Secrecy, authenticated AES-GCM / ChaCha20-Poly1305 encryption, and 1-RTT handshake.
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-4 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search TLS session, cipher suite, SNI hostname..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-[#080c16] border border-slate-700 rounded-md pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-400 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>

        <div className="flex items-center gap-2">
          <select
            value={versionFilter}
            onChange={(e) => setVersionFilter(e.target.value)}
            className="bg-[#080c16] border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All TLS Versions</option>
            <option value="TLS 1.3">TLS 1.3</option>
            <option value="TLS 1.2">TLS 1.2</option>
            <option value="TLS 1.1">TLS 1.1 (Deprecated)</option>
            <option value="TLS 1.0">TLS 1.0 (Deprecated)</option>
          </select>

          <select
            value={pfsFilter}
            onChange={(e) => setPfsFilter(e.target.value)}
            className="bg-[#080c16] border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Forward Secrecy</option>
            <option value="YES">PFS Enabled (ECDHE / DHE)</option>
            <option value="NO">PFS Missing (Static RSA)</option>
          </select>
        </div>
      </div>

      {/* TLS Handshake Detailed Forensic Table */}
      <div className="bg-[#0d1424] border border-slate-800 rounded-lg overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-[#090e1a] text-slate-400 uppercase tracking-wider text-[10px] font-bold border-b border-slate-800">
              <tr>
                <th className="px-4 py-3">Session Ref</th>
                <th className="px-3 py-3">TLS Version</th>
                <th className="px-4 py-3">Negotiated Cipher Suite</th>
                <th className="px-3 py-3">Key Exchange (KEX)</th>
                <th className="px-3 py-3 text-center">PFS</th>
                <th className="px-3 py-3">Encryption Algorithm</th>
                <th className="px-3 py-3">MAC / Hash</th>
                <th className="px-3 py-3">ALPN / SNI</th>
                <th className="px-3 py-3 text-center">Risk</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
              {filteredTLS.length > 0 ? (
                filteredTLS.map((tls, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-4 py-3 font-bold text-cyan-300">
                      {tls.session_id}
                    </td>
                    <td className="px-3 py-3 font-sans">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          tls.tls_version === 'TLS 1.3'
                            ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                            : tls.tls_version === 'TLS 1.2'
                            ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                            : 'bg-red-950 text-red-300 border border-red-800 animate-pulse'
                        }`}
                      >
                        {tls.tls_version}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-200 truncate max-w-[200px]" title={tls.cipher_suite}>
                      {tls.cipher_suite}
                    </td>
                    <td className="px-3 py-3 text-slate-300 font-sans">
                      {tls.key_exchange}
                    </td>
                    <td className="px-3 py-3 text-center font-sans">
                      {tls.forward_secrecy ? (
                        <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                          YES
                        </span>
                      ) : (
                        <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-red-950 text-red-400 border border-red-800">
                          NO
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-3 text-slate-300 font-sans">
                      {tls.encryption_algorithm}
                    </td>
                    <td className="px-3 py-3 text-slate-300 font-sans">
                      {tls.mac_hash}
                    </td>
                    <td className="px-3 py-3 text-slate-400 font-sans text-[10px]">
                      {tls.alpn || tls.sni_server_name || 'None'}
                    </td>
                    <td className="px-3 py-3 text-center font-sans">
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                          tls.risk === 'CRITICAL'
                            ? 'bg-red-950 text-red-400 border-red-800'
                            : tls.risk === 'HIGH'
                            ? 'bg-orange-950 text-orange-400 border-orange-800'
                            : tls.risk === 'MEDIUM'
                            ? 'bg-amber-950 text-amber-400 border-amber-800'
                            : 'bg-blue-950 text-blue-400 border-blue-800'
                        }`}
                      >
                        {tls.risk}
                      </span>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={9} className="px-4 py-8 text-center text-slate-400 font-sans">
                    No TLS sessions match the specified filter criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
