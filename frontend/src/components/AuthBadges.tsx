'use client';

import React, { useState } from 'react';
import { CheckCircle2, XCircle, AlertCircle, HelpCircle, ChevronDown, ChevronUp } from 'lucide-react';
import { ForensicAnalysis } from '../lib/types';

interface AuthBadgesProps {
  analysis: ForensicAnalysis;
}

export function AuthBadges({ analysis }: AuthBadgesProps) {
  const [expanded, setExpanded] = useState<string | null>(null);

  const getStatusColor = (status: string) => {
    switch (status.toUpperCase()) {
      case 'PASS':
        return {
          bg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
          icon: CheckCircle2,
          color: 'text-emerald-400',
        };
      case 'SOFTFAIL':
      case 'NEUTRAL':
        return {
          bg: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
          icon: AlertCircle,
          color: 'text-amber-400',
        };
      case 'FAIL':
      case 'PERMERROR':
      case 'INVALID':
        return {
          bg: 'bg-red-500/10 text-red-400 border-red-500/30',
          icon: XCircle,
          color: 'text-red-400',
        };
      default:
        return {
          bg: 'bg-slate-500/10 text-slate-400 border-slate-500/30',
          icon: HelpCircle,
          color: 'text-slate-400',
        };
    }
  };

  const spfTheme = getStatusColor(analysis.spf_status);
  const dkimTheme = getStatusColor(analysis.dkim_status);
  const dmarcTheme = getStatusColor(analysis.dmarc_status);

  const SpfIcon = spfTheme.icon;
  const DkimIcon = dkimTheme.icon;
  const DmarcIcon = dmarcTheme.icon;

  const toggleExpand = (badge: string) => {
    setExpanded(expanded === badge ? null : badge);
  };

  return (
    <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow-xl flex flex-col justify-between">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
          Protocol Authentication
        </h3>
        <span className="text-[10px] text-slate-400">RFC 7489 Alignment</span>
      </div>

      <div className="grid grid-cols-3 gap-3">
        {/* SPF Badge */}
        <div className="flex flex-col">
          <button
            onClick={() => toggleExpand('spf')}
            className={`flex items-center justify-between px-3 py-2 rounded-lg border text-xs font-semibold transition ${spfTheme.bg}`}
          >
            <div className="flex items-center gap-1.5">
              <SpfIcon className="w-3.5 h-3.5" />
              <span>SPF</span>
            </div>
            <div className="flex items-center gap-1">
              <span className="font-bold">{analysis.spf_status}</span>
              {expanded === 'spf' ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            </div>
          </button>
        </div>

        {/* DKIM Badge */}
        <div className="flex flex-col">
          <button
            onClick={() => toggleExpand('dkim')}
            className={`flex items-center justify-between px-3 py-2 rounded-lg border text-xs font-semibold transition ${dkimTheme.bg}`}
          >
            <div className="flex items-center gap-1.5">
              <DkimIcon className="w-3.5 h-3.5" />
              <span>DKIM</span>
            </div>
            <div className="flex items-center gap-1">
              <span className="font-bold">{analysis.dkim_status}</span>
              {expanded === 'dkim' ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            </div>
          </button>
        </div>

        {/* DMARC Badge */}
        <div className="flex flex-col">
          <button
            onClick={() => toggleExpand('dmarc')}
            className={`flex items-center justify-between px-3 py-2 rounded-lg border text-xs font-semibold transition ${dmarcTheme.bg}`}
          >
            <div className="flex items-center gap-1.5">
              <DmarcIcon className="w-3.5 h-3.5" />
              <span>DMARC</span>
            </div>
            <div className="flex items-center gap-1">
              <span className="font-bold">{analysis.dmarc_status}</span>
              {expanded === 'dmarc' ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            </div>
          </button>
        </div>
      </div>

      {/* Expanded Details Popover */}
      {expanded && (
        <div className="mt-3 p-3 bg-slate-900/90 rounded-lg border border-slate-800 text-xs text-slate-300 transition-all">
          {expanded === 'spf' && (
            <div className="space-y-1">
              <div className="flex justify-between">
                <span className="text-slate-400">Verified SPF Domain:</span>
                <span className="font-mono text-cyan-300">{analysis.spf_domain || 'None'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">RFC 7489 Alignment:</span>
                <span className={analysis.dmarc_alignment_spf ? 'text-emerald-400' : 'text-red-400'}>
                  {analysis.dmarc_alignment_spf ? 'ALIGNED (MATCH)' : 'UNALIGNED (FAIL)'}
                </span>
              </div>
            </div>
          )}

          {expanded === 'dkim' && (
            <div className="space-y-1">
              <div className="flex justify-between">
                <span className="text-slate-400">Signing Domain (d=):</span>
                <span className="font-mono text-cyan-300">{analysis.dkim_domain || 'None'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Selector (s=):</span>
                <span className="font-mono text-cyan-300">{analysis.dkim_selector || 'None'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Alignment:</span>
                <span className={analysis.dmarc_alignment_dkim ? 'text-emerald-400' : 'text-red-400'}>
                  {analysis.dmarc_alignment_dkim ? 'ALIGNED' : 'UNALIGNED'}
                </span>
              </div>
            </div>
          )}

          {expanded === 'dmarc' && (
            <div className="space-y-1">
              <div className="flex justify-between">
                <span className="text-slate-400">Published Policy (p=):</span>
                <span className="font-mono text-cyan-300 uppercase">{analysis.dmarc_policy || 'none'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Alignment Passed:</span>
                <span className={analysis.dmarc_status === 'PASS' ? 'text-emerald-400' : 'text-red-400'}>
                  {analysis.dmarc_status === 'PASS' ? 'YES (VALID)' : 'NO (DISPOSITION)'}
                </span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

