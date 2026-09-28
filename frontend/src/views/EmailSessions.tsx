import React, { useState, useMemo } from 'react';
import {
  Search,
  Filter,
  Download,
  Mail,
  ShieldAlert,
  ArrowUpDown,
  Lock,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  ShieldCheck,
  AlertTriangle,
  Radio
} from 'lucide-react';
import { EmailSession, PCAPAnalysis, Protocol, Severity } from '../types';

interface EmailSessionsProps {
  analysis: PCAPAnalysis;
  onSelectSession: (session: EmailSession) => void;
}

export const EmailSessions: React.FC<EmailSessionsProps> = ({
  analysis,
  onSelectSession
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');
  const [riskFilter, setRiskFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [sortField, setSortField] = useState<keyof EmailSession>('session_id');
  const [sortAsc, setSortAsc] = useState(true);
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 15;

  const filteredSessions = useMemo(() => {
    return analysis.sessions.filter((session) => {
      // Protocol filter
      if (protocolFilter !== 'ALL' && session.protocol !== protocolFilter) return false;
      // Risk filter
      if (riskFilter !== 'ALL' && session.risk !== riskFilter) return false;
      // Status filter
      if (statusFilter !== 'ALL' && session.status !== statusFilter) return false;
      // Search
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        const matchId = session.session_id.toLowerCase().includes(term);
        const matchSrc = session.source_ip.toLowerCase().includes(term);
        const matchDst = session.dest_ip.toLowerCase().includes(term);
        const matchHost = session.client_hostname?.toLowerCase().includes(term);
        const matchCipher = session.cipher_suite?.toLowerCase().includes(term);
        if (!matchId && !matchSrc && !matchDst && !matchHost && !matchCipher) return false;
      }
      return true;
    }).sort((a, b) => {
      const aVal = a[sortField] ?? '';
      const bVal = b[sortField] ?? '';
      if (aVal < bVal) return sortAsc ? -1 : 1;
      if (aVal > bVal) return sortAsc ? 1 : -1;
      return 0;
    });
  }, [analysis.sessions, protocolFilter, riskFilter, statusFilter, searchTerm, sortField, sortAsc]);

  const totalPages = Math.ceil(filteredSessions.length / itemsPerPage) || 1;
  const paginatedSessions = filteredSessions.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  );

  const handleSort = (field: keyof EmailSession) => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(true);
    }
  };

  const exportCSV = () => {
    const headers = [
      'Session ID', 'Protocol', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port',
      'STARTTLS', 'TLS Version', 'Cipher Suite', 'Certificate', 'Risk', 'Status', 'Duration (ms)'
    ];
    const rows = filteredSessions.map(s => [
      s.session_id, s.protocol, s.source_ip, s.source_port, s.dest_ip, s.dest_port,
      s.starttls_requested ? 'YES' : 'NO', s.tls_version || 'None', s.cipher_suite || 'None',
      s.certificate_subject || 'None', s.risk, s.status, s.duration_ms
    ]);
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `mailflow_sessions_${analysis.filename}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const getRiskBadge = (risk: Severity) => {
    switch (risk) {
      case 'CRITICAL':
        return 'bg-red-950/80 text-red-400 border-red-800/80';
      case 'HIGH':
        return 'bg-orange-950/80 text-orange-400 border-orange-800/80';
      case 'MEDIUM':
        return 'bg-amber-950/80 text-amber-400 border-amber-800/80';
      case 'LOW':
        return 'bg-blue-950/80 text-blue-400 border-blue-800/80';
      default:
        return 'bg-slate-800 text-slate-400 border-slate-700';
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'ENCRYPTED':
        return 'bg-emerald-950/60 text-emerald-400 border-emerald-800/50';
      case 'DOWNGRADED':
        return 'bg-red-950/90 text-red-400 border-red-800 animate-pulse';
      case 'PLAINTEXT':
        return 'bg-amber-950/60 text-amber-400 border-amber-800/50';
      default:
        return 'bg-slate-800 text-slate-400';
    }
  };

  return (
    <div className="space-y-4 pb-12">
      {/* Top Filter and Search Bar */}
      <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-4 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search by Session ID, IP address, hostname, cipher..."
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value);
              setCurrentPage(1);
            }}
            className="w-full bg-[#080c16] border border-slate-700 rounded-md pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-400 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>

        {/* Filter Buttons */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Protocol Filter */}
          <select
            value={protocolFilter}
            onChange={(e) => {
              setProtocolFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="bg-[#080c16] border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Protocols ({analysis.total_email_sessions})</option>
            <option value="SMTP">SMTP ({analysis.protocol_distribution.smtp})</option>
            <option value="IMAP">IMAP ({analysis.protocol_distribution.imap})</option>
            <option value="POP3">POP3 ({analysis.protocol_distribution.pop3})</option>
          </select>

          {/* Risk Filter */}
          <select
            value={riskFilter}
            onChange={(e) => {
              setRiskFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="bg-[#080c16] border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Risk Levels</option>
            <option value="CRITICAL">Critical ({analysis.risk_distribution.critical})</option>
            <option value="HIGH">High ({analysis.risk_distribution.high})</option>
            <option value="MEDIUM">Medium ({analysis.risk_distribution.medium})</option>
            <option value="LOW">Low ({analysis.risk_distribution.low})</option>
          </select>

          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="bg-[#080c16] border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Statuses</option>
            <option value="ENCRYPTED">Encrypted</option>
            <option value="PLAINTEXT">Plaintext</option>
            <option value="DOWNGRADED">Downgraded</option>
          </select>

          {/* Export CSV */}
          <button
            onClick={exportCSV}
            className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Forensic Sessions Table */}
      <div className="bg-[#0d1424] border border-slate-800 rounded-lg overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-[#090e1a] text-slate-400 uppercase tracking-wider text-[10px] font-bold border-b border-slate-800">
              <tr>
                <th
                  onClick={() => handleSort('session_id')}
                  className="px-4 py-3 cursor-pointer hover:text-white"
                >
                  <div className="flex items-center gap-1">
                    <span>Session ID</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th
                  onClick={() => handleSort('protocol')}
                  className="px-3 py-3 cursor-pointer hover:text-white"
                >
                  <div className="flex items-center gap-1">
                    <span>Proto</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="px-3 py-3">Source (Client)</th>
                <th className="px-3 py-3">Destination (Server)</th>
                <th className="px-3 py-3 text-center">STARTTLS</th>
                <th
                  onClick={() => handleSort('tls_version')}
                  className="px-3 py-3 cursor-pointer hover:text-white"
                >
                  <div className="flex items-center gap-1">
                    <span>TLS Version</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="px-3 py-3">Negotiated Cipher Suite</th>
                <th className="px-3 py-3">Certificate CN</th>
                <th
                  onClick={() => handleSort('risk')}
                  className="px-3 py-3 text-center cursor-pointer hover:text-white"
                >
                  <div className="flex items-center justify-center gap-1">
                    <span>Risk</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="px-3 py-3 text-center">Status</th>
                <th className="px-4 py-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {paginatedSessions.length > 0 ? (
                paginatedSessions.map((session) => (
                  <tr
                    key={session.session_id}
                    onClick={() => onSelectSession(session)}
                    className="hover:bg-slate-800/40 cursor-pointer transition-colors group"
                  >
                    {/* Session ID */}
                    <td className="px-4 py-3 font-bold text-cyan-300 group-hover:text-cyan-200">
                      {session.session_id}
                    </td>

                    {/* Protocol */}
                    <td className="px-3 py-3 font-sans">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] font-bold">
                        {session.protocol}
                      </span>
                    </td>

                    {/* Source */}
                    <td className="px-3 py-3 text-slate-300 text-[11px]">
                      <div>{session.source_ip}:{session.source_port}</div>
                      {session.client_hostname && (
                        <div className="text-[10px] text-slate-400 truncate max-w-[120px]">
                          {session.client_hostname}
                        </div>
                      )}
                    </td>

                    {/* Destination */}
                    <td className="px-3 py-3 text-slate-300 text-[11px]">
                      <div>{session.dest_ip}:{session.dest_port}</div>
                    </td>

                    {/* STARTTLS */}
                    <td className="px-3 py-3 text-center font-sans">
                      {session.starttls_requested ? (
                        <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/40 font-bold">
                          YES
                        </span>
                      ) : (
                        <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-bold">
                          NO
                        </span>
                      )}
                    </td>

                    {/* TLS Version */}
                    <td className="px-3 py-3 font-sans text-xs">
                      {session.tls_version ? (
                        <span
                          className={`font-semibold ${
                            session.tls_version === 'TLS 1.3'
                              ? 'text-emerald-400'
                              : session.tls_version === 'TLS 1.2'
                              ? 'text-cyan-400'
                              : 'text-red-400 font-bold'
                          }`}
                        >
                          {session.tls_version}
                        </span>
                      ) : (
                        <span className="text-slate-400 text-[11px]">Cleartext</span>
                      )}
                    </td>

                    {/* Cipher Suite */}
                    <td className="px-3 py-3 text-[11px] text-slate-300 max-w-[180px] truncate font-sans" title={session.cipher_suite || 'N/A'}>
                      {session.cipher_suite || <span className="text-slate-400 italic">None (Plaintext)</span>}
                    </td>

                    {/* Certificate */}
                    <td className="px-3 py-3 text-[11px] text-slate-400 max-w-[140px] truncate font-sans">
                      {session.certificate_subject || <span className="text-slate-400">-</span>}
                    </td>

                    {/* Risk */}
                    <td className="px-3 py-3 text-center font-sans">
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${getRiskBadge(session.risk)}`}>
                        {session.risk}
                      </span>
                    </td>

                    {/* Status */}
                    <td className="px-3 py-3 text-center font-sans">
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${getStatusBadge(session.status)}`}>
                        {session.status}
                      </span>
                    </td>

                    {/* Action */}
                    <td className="px-4 py-3 text-right font-sans">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectSession(session);
                        }}
                        className="text-cyan-400 hover:text-cyan-300 text-xs flex items-center justify-end gap-1 ml-auto font-semibold"
                      >
                        <span>Inspect</span>
                        <ExternalLink className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={11} className="px-4 py-12 text-center text-slate-400 font-sans">
                    No email sessions match your filter criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Controls */}
        <div className="bg-[#090e1a] px-4 py-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <div>
            Showing <span className="text-slate-200 font-bold">{Math.min(filteredSessions.length, (currentPage - 1) * itemsPerPage + 1)}</span> to{' '}
            <span className="text-slate-200 font-bold">{Math.min(filteredSessions.length, currentPage * itemsPerPage)}</span> of{' '}
            <span className="text-slate-200 font-bold">{filteredSessions.length}</span> sessions
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="p-1 rounded bg-slate-800 disabled:opacity-30 hover:bg-slate-700 text-slate-300"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="font-mono">
              Page {currentPage} of {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="p-1 rounded bg-slate-800 disabled:opacity-30 hover:bg-slate-700 text-slate-300"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
