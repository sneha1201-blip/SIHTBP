'use client';

import React, { useState } from 'react';
import { Eye, Code2, Sparkles, AlertOctagon } from 'lucide-react';
import { ForensicAnalysis } from '../lib/types';

interface NlpIntentViewerProps {
  bodyPlain?: string;
  bodyHtml?: string;
  bodyText?: string;
  subject?: string;
  analysis?: ForensicAnalysis;
}

export function NlpIntentViewer({ bodyPlain, bodyHtml, bodyText, subject, analysis }: NlpIntentViewerProps) {
  const [viewMode, setViewMode] = useState<'annotated' | 'raw'>('annotated');

  const textToRender = bodyPlain || bodyText || 'No plaintext content available.';

  // Highlight rules for AI cues
  const highlightAiEntities = (content: string) => {
    // Regex for financial triggers (Account, IFSC, RTGS, Amounts)
    const financialRegex = /(HDFC[0-9]{7}|Account\s*:\s*[0-9]+|RTGS|remit(?:tance)?|escrow\s*account|Rs\.?\s*[0-9,]+)/gi;
    // Regex for urgency triggers
    const urgencyRegex = /(immediately|within 24 hours|before 4:00 PM today|URGENT & CONFIDENTIAL|mandatory|reduction in sanctioned intake|zero-admission)/gi;
    // Regex for credential lure triggers
    const credRegex = /(login immediately|verify credentials|biometric re-validation|confirm your credentials|password expired)/gi;

    const parts = content.split('\n');

    return parts.map((line, lineIdx) => {
      // Split line by detected keywords
      const words = line.split(/(\s+)/);
      return (
        <div key={lineIdx} className="leading-relaxed min-h-[1.25rem]">
          {line.split(/(HDFC[0-9]{7}|Account\s*:\s*[0-9]+|RTGS|remit(?:tance)?|escrow\s*account|Rs\.?\s*[0-9,]+|immediately|within 24 hours|before 4:00 PM today|URGENT & CONFIDENTIAL|mandatory|reduction in sanctioned intake|zero-admission|login immediately|verify credentials|biometric re-validation|confirm your credentials|password expired)/gi).map((token, idx) => {
            if (financialRegex.test(token)) {
              return (
                <span
                  key={idx}
                  title="AI Flag: Financial Diversion / Wire Remittance"
                  className="bg-red-500/20 text-red-300 font-bold px-1.5 py-0.5 rounded border border-red-500/40 inline-block my-0.5"
                >
                  {token}
                </span>
              );
            } else if (urgencyRegex.test(token)) {
              return (
                <span
                  key={idx}
                  title="AI Flag: Psychological Urgency & Coercion Trigger"
                  className="bg-amber-500/20 text-amber-300 font-semibold px-1 py-0.5 rounded border border-amber-500/40 inline-block my-0.5"
                >
                  {token}
                </span>
              );
            } else if (credRegex.test(token)) {
              return (
                <span
                  key={idx}
                  title="AI Flag: Credential Harvesting Phishing Lure"
                  className="bg-purple-500/20 text-purple-300 font-semibold px-1 py-0.5 rounded border border-purple-500/40 inline-block my-0.5"
                >
                  {token}
                </span>
              );
            }
            return <span key={idx}>{token}</span>;
          })}
        </div>
      );
    });
  };

  return (
    <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow-xl flex flex-col h-full">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
          <Sparkles className="w-4 h-4 text-cyan-400" /> AI Content & Intent Semantic Overlay
        </h3>

        {/* View Toggle */}
        <div className="flex items-center gap-1 bg-slate-900 p-0.5 rounded-lg border border-slate-800 text-xs">
          <button
            onClick={() => setViewMode('annotated')}
            className={`px-2.5 py-1 rounded font-medium transition flex items-center gap-1 ${
              viewMode === 'annotated' ? 'bg-cyan-600 text-white shadow-sm' : 'text-slate-400 hover:text-white'
            }`}
          >
            <Eye className="w-3 h-3" /> Annotated
          </button>
          <button
            onClick={() => setViewMode('raw')}
            className={`px-2.5 py-1 rounded font-medium transition flex items-center gap-1 ${
              viewMode === 'raw' ? 'bg-cyan-600 text-white shadow-sm' : 'text-slate-400 hover:text-white'
            }`}
          >
            <Code2 className="w-3 h-3" /> Raw Text
          </button>
        </div>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap items-center gap-3 mb-3 text-[11px] text-slate-400 pb-2 border-b border-cyber-border/40">
        <span className="flex items-center gap-1">
          <span className="w-2.5 h-2.5 rounded-full bg-red-500/80"></span> Wire / Payment Diversion
        </span>
        <span className="flex items-center gap-1">
          <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80"></span> Artificial Urgency & Coercion
        </span>
        <span className="flex items-center gap-1">
          <span className="w-2.5 h-2.5 rounded-full bg-purple-500/80"></span> Credential Harvesting Lure
        </span>
      </div>

      {/* Body Content Container */}
      <div className="flex-1 overflow-y-auto max-h-[300px] p-3.5 bg-slate-950/80 rounded-lg border border-slate-900 font-mono text-xs text-slate-200">
        {viewMode === 'annotated' ? (
          highlightAiEntities(textToRender)
        ) : (
          <pre className="whitespace-pre-wrap font-mono text-slate-300">{textToRender}</pre>
        )}
      </div>
    </div>
  );
}

