'use client';

import React from 'react';
import { AlertTriangle, UserX, Globe, ArrowRightLeft } from 'lucide-react';
import { EmailDossier, ForensicAnalysis } from '../lib/types';

interface HeaderMismatchTableProps {
  email: EmailDossier;
  analysis: ForensicAnalysis;
}

export function HeaderMismatchTable({ email, analysis }: HeaderMismatchTableProps) {
  const isReplyToMismatch = email.reply_to && email.sender_email && email.reply_to.toLowerCase() !== email.sender_email.toLowerCase();
  const isReturnPathMismatch = email.return_path && email.sender_email && email.return_path.toLowerCase() !== email.sender_email.toLowerCase();

  return (
    <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow-xl">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
          <ArrowRightLeft className="w-4 h-4 text-cyan-400" /> Header Identity Mismatch Matrix
        </h3>
        {/* Warning Flags */}
        <div className="flex items-center gap-2">
          {analysis.display_spoof_flag && (
            <span className="text-[10px] px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/30 font-bold flex items-center gap-1">
              <UserX className="w-3 h-3" /> VIP Spoof
            </span>
          )}
          {analysis.homograph_flag && (
            <span className="text-[10px] px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30 font-bold flex items-center gap-1">
              <Globe className="w-3 h-3" /> Cyrillic Homograph
            </span>
          )}
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-cyber-border text-slate-400 text-left font-semibold">
              <th className="pb-2 pl-2">Header Field</th>
              <th className="pb-2">Parsed Identity & Address</th>
              <th className="pb-2 text-right pr-2">Forensic Correlation</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-cyber-border/40">
            {/* From Header */}
            <tr className="hover:bg-slate-900/40 transition">
              <td className="py-2.5 pl-2 font-mono text-slate-400 font-medium">From:</td>
              <td className="py-2.5">
                <div className="text-white font-medium">{email.sender_display || '(None)'}</div>
                <div className="text-cyan-300 font-mono text-[11px]">&lt;{email.sender_email}&gt;</div>
              </td>
              <td className="py-2.5 pr-2 text-right">
                <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                  Claimed Sender
                </span>
              </td>
            </tr>

            {/* Return-Path Header */}
            <tr className="hover:bg-slate-900/40 transition">
              <td className="py-2.5 pl-2 font-mono text-slate-400 font-medium">Return-Path:</td>
              <td className="py-2.5 font-mono text-slate-200">
                {email.return_path ? `&lt;${email.return_path}&gt;` : '(None)'}
              </td>
              <td className="py-2.5 pr-2 text-right">
                {isReturnPathMismatch ? (
                  <span className="text-[10px] px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30 font-semibold">
                    Envelope Divergence
                  </span>
                ) : (
                  <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                    Matches Sender
                  </span>
                )}
              </td>
            </tr>

            {/* Reply-To Header */}
            <tr className="hover:bg-slate-900/40 transition">
              <td className="py-2.5 pl-2 font-mono text-slate-400 font-medium">Reply-To:</td>
              <td className="py-2.5 font-mono">
                {email.reply_to ? (
                  <span className={isReplyToMismatch ? 'text-red-400 font-bold' : 'text-slate-200'}>
                    &lt;{email.reply_to}&gt;
                  </span>
                ) : (
                  <span className="text-slate-400">(None)</span>
                )}
              </td>
              <td className="py-2.5 pr-2 text-right">
                {isReplyToMismatch ? (
                  <span className="text-[10px] px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/30 font-bold animate-pulse flex items-center gap-1 justify-end">
                    <AlertTriangle className="w-3 h-3" /> Diverts to External Inbox
                  </span>
                ) : (
                  <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                    Direct Response
                  </span>
                )}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}

