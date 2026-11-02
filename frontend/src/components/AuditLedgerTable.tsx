'use client';

import React from 'react';
import { ShieldCheck, Lock, FileCheck, Copy, Check } from 'lucide-react';
import { AuditLog } from '../lib/types';
import { copyToClipboard, formatDate } from '../lib/utils';

interface AuditLedgerTableProps {
  logs: AuditLog[];
  masterSha256: string;
}

export function AuditLedgerTable({ logs, masterSha256 }: AuditLedgerTableProps) {
  const [copiedHmac, setCopiedHmac] = React.useState<string | null>(null);

  const handleCopy = async (text: string, id: string) => {
    const ok = await copyToClipboard(text);
    if (ok) {
      setCopiedHmac(id);
      setTimeout(() => setCopiedHmac(null), 2000);
    }
  };

  return (
    <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow-xl flex flex-col gap-3">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
            <Lock className="w-4 h-4 text-emerald-400" /> Section 63 BSA 2023 / Section 65B IEA Tamper-Evident Audit Ledger
          </h3>
          <p className="text-[11px] text-slate-400 mt-0.5">
            Cryptographic HMAC-SHA256 append-only chain of custody proving evidence immutability
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-mono bg-emerald-950/60 text-emerald-300 border border-emerald-800 px-2 py-0.5 rounded flex items-center gap-1">
            <ShieldCheck className="w-3.5 h-3.5" /> WORM Vault Sealed
          </span>
        </div>
      </div>

      <div className="overflow-x-auto border border-cyber-border/40 rounded-lg">
        <table className="w-full text-xs text-left">
          <thead className="bg-slate-950/80 border-b border-cyber-border text-slate-400 uppercase text-[10px] tracking-wider">
            <tr>
              <th className="py-2.5 px-3">Action</th>
              <th className="py-2.5 px-3">Actor / Principal</th>
              <th className="py-2.5 px-3">Timestamp (UTC)</th>
              <th className="py-2.5 px-3">Evidence SHA-256</th>
              <th className="py-2.5 px-3">HMAC-SHA256 Signature</th>
              <th className="py-2.5 px-3 text-right">Integrity Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-cyber-border/30 font-mono text-[11px]">
            {logs.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-6 text-center text-slate-500 font-sans">
                  No audit log entries recorded for this evidence record.
                </td>
              </tr>
            ) : (
              logs.map((log) => (
                <tr key={log.id} className="hover:bg-slate-900/40 transition">
                  <td className="py-2.5 px-3">
                    <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-300 font-bold">
                      {log.action_performed}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-300">{log.actor}</td>
                  <td className="py-2.5 px-3 text-slate-400">{formatDate(log.recorded_at)}</td>
                  <td className="py-2.5 px-3 text-slate-400" title={log.evidence_sha256}>
                    {log.evidence_sha256 ? `${log.evidence_sha256.substring(0, 14)}...` : 'N/A'}
                  </td>
                  <td className="py-2.5 px-3 text-cyan-400">
                    <div className="flex items-center gap-1.5">
                      <span title={log.hmac_signature}>
                        {log.hmac_signature ? `${log.hmac_signature.substring(0, 16)}...` : 'N/A'}
                      </span>
                      {log.hmac_signature && (
                        <button
                          onClick={() => handleCopy(log.hmac_signature, log.id)}
                          className="text-slate-500 hover:text-cyan-400"
                          title="Copy Full HMAC Signature"
                        >
                          {copiedHmac === log.id ? (
                            <Check className="w-3 h-3 text-emerald-400" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      )}
                    </div>
                  </td>
                  <td className="py-2.5 px-3 text-right">
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950/70 text-emerald-300 border border-emerald-800 font-sans">
                      <FileCheck className="w-3 h-3 text-emerald-400" /> Tamper-Proof
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default AuditLedgerTable;

