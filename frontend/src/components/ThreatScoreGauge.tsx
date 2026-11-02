'use client';

import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, Flame } from 'lucide-react';

import { ForensicAnalysis } from '../lib/types';

interface ThreatScoreGaugeProps {
  score?: number;
  verdict?: 'BENIGN' | 'SUSPICIOUS' | 'PHISHING' | 'BEC' | 'MALICIOUS';
  subscores?: {
    auth: number;
    header: number;
    nlp: number;
    url: number;
    osint: number;
    attachment: number;
  };
  analysis?: ForensicAnalysis;
}

export function ThreatScoreGauge({ score, verdict, subscores, analysis }: ThreatScoreGaugeProps) {
  const effectiveScore = analysis ? analysis.threat_score : (score ?? 0);
  const effectiveVerdict = analysis ? analysis.verdict : (verdict ?? 'BENIGN');
  const effectiveSubscores = analysis ? analysis.score_breakdown?.subscores : subscores;

  // Determine color theme based on score thresholds
  let strokeColor = '#10b981'; // Green: Benign (0-29)
  let badgeBg = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
  let Icon = ShieldCheck;

  if (effectiveScore >= 90) {
    strokeColor = '#ef4444'; // Red: Malicious (90-100)
    badgeBg = 'bg-red-500/10 text-red-400 border-red-500/30';
    Icon = Flame;
  } else if (effectiveScore >= 70) {
    strokeColor = '#f97316'; // Orange: BEC/Phish (70-89)
    badgeBg = 'bg-orange-500/10 text-orange-400 border-orange-500/30';
    Icon = ShieldAlert;
  } else if (effectiveScore >= 30) {
    strokeColor = '#f59e0b'; // Yellow: Suspicious (30-69)
    badgeBg = 'bg-amber-500/10 text-amber-400 border-amber-500/30';
    Icon = AlertTriangle;
  }

  // Circular progress calculations (Radius = 54, Circumference = 2 * PI * 54 = 339.29)
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (Math.min(100, Math.max(0, effectiveScore)) / 100) * circumference;

  return (
    <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow-xl flex flex-col justify-between">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
          <Icon className="w-4 h-4 text-cyan-400" /> Composite Threat Score
        </h3>
        <span className={`text-xs px-2.5 py-0.5 rounded-full font-bold border ${badgeBg}`}>
          {effectiveVerdict}
        </span>
      </div>

      <div className="flex items-center justify-center py-2 relative">
        <svg className="w-36 h-36 transform -rotate-90">
          {/* Background Track */}
          <circle
            cx="72"
            cy="72"
            r={radius}
            stroke="#1e293b"
            strokeWidth="10"
            fill="transparent"
          />
          {/* Animated Value Arc */}
          <circle
            cx="72"
            cy="72"
            r={radius}
            stroke={strokeColor}
            strokeWidth="10"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Center Score readout */}
        <div className="absolute flex flex-col items-center justify-center">
          <span className="text-3xl font-extrabold text-white tracking-tight">{effectiveScore.toFixed(0)}</span>
          <span className="text-[10px] uppercase font-semibold text-slate-400">out of 100</span>
        </div>
      </div>

      {/* Subscore metric bars */}
      {effectiveSubscores && (
        <div className="mt-3 pt-3 border-t border-cyber-border/60 grid grid-cols-3 gap-2 text-center">
          <div className="bg-slate-900/60 p-1.5 rounded border border-slate-800">
            <span className="text-[9px] uppercase text-slate-400 block font-medium">Auth (25%)</span>
            <span className="text-xs font-bold text-slate-200">{effectiveSubscores.auth}</span>
          </div>
          <div className="bg-slate-900/60 p-1.5 rounded border border-slate-800">
            <span className="text-[9px] uppercase text-slate-400 block font-medium">Header (20%)</span>
            <span className="text-xs font-bold text-slate-200">{effectiveSubscores.header}</span>
          </div>
          <div className="bg-slate-900/60 p-1.5 rounded border border-slate-800">
            <span className="text-[9px] uppercase text-slate-400 block font-medium">NLP (20%)</span>
            <span className="text-xs font-bold text-slate-200">{effectiveSubscores.nlp}</span>
          </div>
        </div>
      )}
    </div>
  );
}

