'use client';

import React, { useState } from 'react';
import { ShieldCheck, Copy, Check, Filter, Search, ToggleLeft, ToggleRight, Download } from 'lucide-react';
import { ThreatIndicator } from '../lib/types';
import { defangString, refangString, copyToClipboard } from '../lib/utils';

interface IocDataTableProps {
  indicators: ThreatIndicator[];
}

export function IocDataTable({ indicators }: IocDataTableProps) {
  const [filterType, setFilterType] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [isDefanged, setIsDefanged] = useState<boolean>(true);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [copiedAll, setCopiedAll] = useState<boolean>(false);

  const filtered = indicators.filter((ioc) => {
    const matchesType = filterType === 'ALL' || ioc.ioc_type === filterType;
    const matchesSearch =
      ioc.ioc_value.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (ioc.context || '').toLowerCase().includes(searchQuery.toLowerCase());
    return matchesType && matchesSearch;
  });

  const handleCopySingle = async (ioc: ThreatIndicator) => {
    const text = isDefanged ? defangString(ioc.ioc_value) : refangString(ioc.ioc_value);
    const ok = await copyToClipboard(text);
    if (ok) {
      setCopiedId(ioc.id);
      setTimeout(() => setCopiedId(null), 1500);
    }
  };

  const handleCopyAll = async () => {
    const allText = filtered
      .map((ioc) => `${ioc.ioc_type}: ${isDefanged ? defangString(ioc.ioc_value) : refangString(ioc.ioc_value)}`)
      .join('\n');
    const ok = await copyToClipboard(allText);
    if (ok) {
      setCopiedAll(true);
      setTimeout(() => setCopiedAll(false), 2000);
    }
  };

  return (
    <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow-xl flex flex-col h-full">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
            <ShieldCheck className="w-4 h-4 text-cyan-400" /> Extracted Indicators of Compromise (IoCs)
          </h3>
          <p className="text-[11px] text-slate-400 mt-0.5">
            {indicators.length} total indicators extracted across body, headers & attachments
          </p>
        </div>

        {/* Global Action Bar */}
        <div className="flex items-center gap-2">
          {/* Defang Toggle Button */}
          <button
            onClick={() => setIsDefanged(!isDefanged)}
            className={`flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-semibold border transition ${isDefanged
                ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30'
                : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
              }`}
          >
            {isDefanged ? <ToggleRight className="w-4 h-4" /> : <ToggleLeft className="w-4 h-4" />}
            <span>{isDefanged ? 'Defanged (Safe)' : 'Refanged (Active)'}</span>
          </button>

          {/* Copy All Button */}
          <button
            onClick={handleCopyAll}
            className="flex items-center gap-1 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 px-2.5 py-1 rounded-lg text-xs font-medium transition"
          >
            {copiedAll ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedAll ? 'Copied All' : 'Copy List'}</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-2 mb-3">
        {/* Type Filter Pills */}
        <div className="flex items-center gap-1 overflow-x-auto w-full sm:w-auto">
          {['ALL', 'URL', 'DOMAIN', 'IP', 'HASH', 'EMAIL_ADDR'].map((type) => (
            <button
              key={type}
              onClick={() => setFilterType(type)}
              className={`px-2.5 py-1 rounded text-[11px] font-semibold transition ${filterType === type
                  ? 'bg-cyan-600 text-white'
                  : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
                }`}
            >
              {type}
            </button>
          ))}
        </div>

        {/* Search input */}
        <div className="relative w-full sm:w-56">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
          <input
            type="text"
            placeholder="Filter indicators..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>

      {/* Indicators Table */}
      <div className="overflow-x-auto flex-1 max-h-[320px] overflow-y-auto border border-cyber-border/40 rounded-lg">
        <table className="w-full text-xs text-left">
          <thead className="bg-slate-950/80 sticky top-0 border-b border-cyber-border text-slate-400 uppercase text-[10px] tracking-wider">
            <tr>
              <th className="py-2 px-3">Type</th>
              <th className="py-2 px-3">Indicator Value</th>
              <th className="py-2 px-3">Context</th>
              <th className="py-2 px-3">Reputation</th>
              <th className="py-2 px-3 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-cyber-border/30 font-mono">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={5} className="py-6 text-center text-slate-500 font-sans">
                  No threat indicators matching filter criteria.
                </td>
              </tr>
            ) : (
              filtered.map((ioc) => {
                const displayVal = isDefanged ? defangString(ioc.ioc_value) : refangString(ioc.ioc_value);
                const rep = ioc.reputation_score;
                const repColor =
                  rep && rep >= 80
                    ? 'text-red-400 bg-red-500/10 border-red-500/30'
                    : rep && rep >= 50
                      ? 'text-amber-400 bg-amber-500/10 border-amber-500/30'
                      : 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';

                return (
                  <tr key={ioc.id} className="hover:bg-slate-900/50 transition">
                    <td className="py-2 px-3 font-sans font-bold">
                      <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700">
                        {ioc.ioc_type}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-slate-200 max-w-[280px] truncate" title={displayVal}>
                      {displayVal}
                    </td>
                    <td className="py-2 px-3 font-sans text-slate-400 text-[11px]">
                      {ioc.context || 'Unknown'}
                    </td>
                    <td className="py-2 px-3 font-sans">
                      {rep !== undefined ? (
                        <span className={`text-[10px] px-2 py-0.5 rounded font-bold border ${repColor}`}>
                          {rep.toFixed(0)}/100
                        </span>
                      ) : (
                        <span className="text-slate-500">-</span>
                      )}
                    </td>
                    <td className="py-2 px-3 text-right">
                      <button
                        onClick={() => handleCopySingle(ioc)}
                        className="p-1 hover:text-cyan-300 text-slate-400 transition"
                        title="Copy indicator"
                      >
                        {copiedId === ioc.id ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
