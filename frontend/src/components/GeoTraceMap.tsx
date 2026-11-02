'use client';

import React, { useState } from 'react';
import dynamic from 'next/dynamic';
import { HeaderHop } from '../lib/types';
import { Globe, Server, ArrowRight, ShieldCheck, ShieldAlert, Clock, MapPin, Eye } from 'lucide-react';

// Dynamic import with SSR disabled to prevent Leaflet "window is not defined" error
const DynamicGeoTraceMapInner = dynamic(
  () => import('./GeoTraceMapInner'),
  {
    ssr: false,
    loading: () => (
      <div className="w-full h-[400px] rounded-xl bg-slate-950/60 border border-cyber-border flex flex-col items-center justify-center gap-3">
        <div className="w-10 h-10 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin"></div>
        <p className="text-xs text-slate-400 font-mono">Initializing Leaflet CartoDB Dark Matter Engine...</p>
      </div>
    ),
  }
);

interface GeoTraceMapProps {
  hops: HeaderHop[];
}

export function GeoTraceMap({ hops }: GeoTraceMapProps) {
  const [selectedHop, setSelectedHop] = useState<HeaderHop | null>(null);

  // Chronological sort
  const sortedHops = [...hops].sort((a, b) => a.hop_order - b.hop_order);

  return (
    <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow-xl flex flex-col gap-5">
      {/* Section Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
            <Globe className="w-4 h-4 text-cyan-400" /> Hop-by-Hop Visual Geotrace & MTA Relay Chain
          </h3>
          <p className="text-[11px] text-slate-400 mt-0.5">
            Reverse hop-traversal analysis from recipient MX back to originating gateway
          </p>
        </div>
        <div className="text-right">
          <span className="text-xs font-mono px-2.5 py-1 rounded bg-slate-950 border border-slate-800 text-cyan-300">
            {hops.length} Total Hops Recorded
          </span>
        </div>
      </div>

      {/* Dynamic Leaflet Map */}
      <DynamicGeoTraceMapInner
        hops={hops}
        selectedHopOrder={selectedHop?.hop_order}
        onSelectHop={(hop) => setSelectedHop(hop)}
      />

      {/* Hop Relay Chain Timeline */}
      <div className="space-y-2">
        <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center justify-between">
          <span>MTA Relay Sequence (Chronological)</span>
          <span className="text-[10px] text-slate-500">Earliest Hop #1 &rarr; Destination MX</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
          {sortedHops.map((hop, idx) => {
            const isOrigin = idx === 0;
            const isFinal = idx === sortedHops.length - 1 && sortedHops.length > 1;
            const isSelected = selectedHop?.hop_order === hop.hop_order;

            return (
              <div
                key={hop.id || `timeline-${hop.hop_order}`}
                onClick={() => setSelectedHop(hop)}
                className={`p-3 rounded-lg border cursor-pointer transition flex flex-col justify-between ${
                  isSelected
                    ? 'bg-cyan-950/40 border-cyan-500/80 shadow-md shadow-cyan-500/10'
                    : isOrigin
                    ? 'bg-rose-950/20 border-rose-500/30 hover:border-rose-500/60'
                    : isFinal
                    ? 'bg-emerald-950/20 border-emerald-500/30 hover:border-emerald-500/60'
                    : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-mono font-bold text-slate-200 flex items-center gap-1">
                      <span className={`w-2 h-2 rounded-full ${
                        isOrigin ? 'bg-rose-500' : isFinal ? 'bg-emerald-500' : 'bg-amber-400'
                      }`} />
                      Hop #{hop.hop_order}
                    </span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono font-semibold ${
                      isOrigin ? 'bg-rose-500/20 text-rose-300' : isFinal ? 'bg-emerald-500/20 text-emerald-300' : 'bg-slate-800 text-slate-300'
                    }`}>
                      {isOrigin ? 'ORIGIN' : isFinal ? 'MX' : 'RELAY'}
                    </span>
                  </div>

                  <div className="font-mono text-xs font-semibold text-white mb-1 flex items-center justify-between">
                    <span>{hop.hop_ip}</span>
                    {hop.is_reliable ? (
                      <span title="Cryptographically & downstream authenticated" className="text-emerald-400 text-[10px] flex items-center gap-0.5">
                        <ShieldCheck className="w-3 h-3" /> Reliable
                      </span>
                    ) : (
                      <span title="Unverified or private hop" className="text-amber-400 text-[10px] flex items-center gap-0.5">
                        <ShieldAlert className="w-3 h-3" /> Unverified
                      </span>
                    )}
                  </div>

                  <div className="text-[11px] text-slate-400 truncate mb-1" title={hop.from_mta || 'Unknown MTA'}>
                    From: <span className="text-slate-300">{hop.from_mta || 'Direct Client'}</span>
                  </div>

                  <div className="text-[11px] text-slate-400 truncate mb-2" title={hop.by_mta || 'Unknown MTA'}>
                    By: <span className="text-slate-300">{hop.by_mta || 'Unknown'}</span>
                  </div>
                </div>

                <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px]">
                  <span className="text-slate-400 flex items-center gap-1 truncate max-w-[130px]">
                    <MapPin className="w-3 h-3 text-cyan-400 shrink-0" />
                    {hop.geo_country ? `${hop.geo_city ? hop.geo_city + ', ' : ''}${hop.geo_country}` : 'Internal / Private'}
                  </span>
                  {hop.delay_seconds !== null && hop.delay_seconds !== undefined && (
                    <span className="text-amber-400 font-mono text-[10px] flex items-center gap-0.5">
                      <Clock className="w-2.5 h-2.5" /> +{hop.delay_seconds.toFixed(1)}s
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export default GeoTraceMap;

