'use client';

import React, { useEffect } from 'react';
import { MapContainer, TileLayer, Marker, Popup, Polyline, useMap } from 'react-leaflet';
import L from 'leaflet';
import { HeaderHop } from '../lib/types';
import { Globe, Shield, AlertTriangle, Clock, Server, ArrowRight } from 'lucide-react';

interface GeoTraceMapInnerProps {
  hops: HeaderHop[];
  selectedHopOrder?: number | null;
  onSelectHop?: (hop: HeaderHop) => void;
}

// Map helper to auto-fit bounds and invalidate size to prevent grey tiles
function MapLifecycleHelper({ positions }: { positions: [number, number][] }) {
  const map = useMap();
  useEffect(() => {
    // Immediate and delayed size invalidation for flex/grid container sizing
    map.invalidateSize();
    const timer = setTimeout(() => {
      map.invalidateSize();
    }, 200);

    if (positions.length === 1) {
      map.setView(positions[0], 5);
    } else if (positions.length > 1) {
      const bounds = L.latLngBounds(positions);
      map.fitBounds(bounds, { padding: [40, 40], maxZoom: 8 });
    }

    return () => clearTimeout(timer);
  }, [positions, map]);
  return null;
}

export default function GeoTraceMapInner({ hops, selectedHopOrder, onSelectHop }: GeoTraceMapInnerProps) {
  // Sort hops chronologically by hop_order
  const sortedHops = [...hops].sort((a, b) => a.hop_order - b.hop_order);
  
  // Extract geolocated hops with valid lat and lon
  const geoHops = sortedHops.filter(
    (h) => typeof h.geo_lat === 'number' && typeof h.geo_lon === 'number' && !isNaN(h.geo_lat) && !isNaN(h.geo_lon)
  );

  const polylinePositions: [number, number][] = geoHops.map((h) => [h.geo_lat!, h.geo_lon!]);

  // Fallback center: New Delhi or first hop
  const defaultCenter: [number, number] = polylinePositions.length > 0 
    ? polylinePositions[0] 
    : [28.6139, 77.2090]; // New Delhi

  const createMarkerIcon = (hop: HeaderHop, isOrigin: boolean, isFinal: boolean) => {
    if (isOrigin) {
      return L.divIcon({
        className: 'custom-radar-marker',
        html: `
          <div class="relative flex items-center justify-center">
            <span class="absolute w-8 h-8 rounded-full bg-rose-500/40 animate-ping"></span>
            <span class="relative w-5 h-5 rounded-full bg-rose-500 border-2 border-white shadow-lg shadow-rose-500/80 flex items-center justify-center text-[10px] font-black text-white">
              ${hop.hop_order}
            </span>
          </div>
        `,
        iconSize: [32, 32],
        iconAnchor: [16, 16],
      });
    }

    if (isFinal) {
      return L.divIcon({
        className: 'custom-mx-marker',
        html: `
          <div class="relative flex items-center justify-center">
            <span class="w-5 h-5 rounded-full bg-emerald-500 border-2 border-white shadow-lg shadow-emerald-500/80 flex items-center justify-center text-[9px] font-black text-white">
              MX
            </span>
          </div>
        `,
        iconSize: [28, 28],
        iconAnchor: [14, 14],
      });
    }

    return L.divIcon({
      className: 'custom-relay-marker',
      html: `
        <div class="relative flex items-center justify-center">
          <span class="w-4 h-4 rounded-full bg-amber-400 border border-slate-900 shadow-md shadow-amber-400/50 flex items-center justify-center text-[9px] font-bold text-slate-950">
            ${hop.hop_order}
          </span>
        </div>
      `,
      iconSize: [24, 24],
      iconAnchor: [12, 12],
    });
  };

  return (
    <div className="relative w-full h-[400px] rounded-xl overflow-hidden border border-cyber-border shadow-2xl">
      <MapContainer
        center={defaultCenter}
        zoom={3}
        scrollWheelZoom={true}
        style={{ height: '100%', width: '100%', background: '#070b14' }}
      >
        {/* CartoDB Dark Matter Tiles */}
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>'
          url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
          maxZoom={19}
          subdomains="abcd"
        />

        <MapLifecycleHelper positions={polylinePositions} />

        {/* Flight Path Polyline */}
        {polylinePositions.length > 1 && (
          <Polyline
            positions={polylinePositions}
            pathOptions={{
              color: '#06b6d4',
              weight: 3,
              opacity: 0.85,
              dashArray: '8, 8',
            }}
          />
        )}

        {/* Hop Markers */}
        {geoHops.map((hop, idx) => {
          const isOrigin = idx === 0;
          const isFinal = idx === geoHops.length - 1 && geoHops.length > 1;
          const pos: [number, number] = [hop.geo_lat!, hop.geo_lon!];

          return (
            <Marker
              key={hop.id || `hop-${hop.hop_order}`}
              position={pos}
              icon={createMarkerIcon(hop, isOrigin, isFinal)}
              eventHandlers={{
                click: () => onSelectHop && onSelectHop(hop),
              }}
            >
              <Popup className="cyber-popup">
                <div className="p-1 min-w-[220px] text-slate-200">
                  <div className="flex items-center justify-between pb-1.5 border-b border-slate-700 mb-2">
                    <span className="text-[11px] font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1">
                      <Server className="w-3.5 h-3.5" /> Hop #{hop.hop_order}
                    </span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono font-semibold ${
                      isOrigin ? 'bg-rose-500/20 text-rose-300' : isFinal ? 'bg-emerald-500/20 text-emerald-300' : 'bg-amber-500/20 text-amber-300'
                    }`}>
                      {isOrigin ? 'ORIGIN' : isFinal ? 'DESTINATION MX' : 'RELAY'}
                    </span>
                  </div>

                  <div className="space-y-1 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">IP:</span>
                      <span className="font-mono font-semibold text-white">{hop.hop_ip}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Location:</span>
                      <span className="text-slate-200">{hop.geo_city ? `${hop.geo_city}, ` : ''}{hop.geo_country || 'Unknown'}</span>
                    </div>
                    {hop.asn_org && (
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400">ASN:</span>
                        <span className="font-mono text-cyan-300 truncate max-w-[140px]" title={hop.asn_org}>
                          {hop.asn_number ? `AS${hop.asn_number} ` : ''}{hop.asn_org}
                        </span>
                      </div>
                    )}
                    {hop.delay_seconds !== null && hop.delay_seconds !== undefined && (
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400">Transit Delay:</span>
                        <span className="text-amber-400 font-mono flex items-center gap-0.5">
                          <Clock className="w-3 h-3" /> +{hop.delay_seconds.toFixed(2)}s
                        </span>
                      </div>
                    )}
                    {(hop.is_tor || hop.is_vpn || hop.is_datacenter) && (
                      <div className="pt-1.5 mt-1 border-t border-slate-800 flex flex-wrap gap-1">
                        {hop.is_tor && <span className="text-[10px] bg-rose-950 text-rose-300 border border-rose-800 px-1 rounded font-bold">TOR EXIT</span>}
                        {hop.is_vpn && <span className="text-[10px] bg-amber-950 text-amber-300 border border-amber-800 px-1 rounded font-bold">COMMERCIAL VPN</span>}
                        {hop.is_datacenter && <span className="text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-800 px-1 rounded font-bold">HOSTING/DC</span>}
                      </div>
                    )}
                  </div>
                </div>
              </Popup>
            </Marker>
          );
        })}
      </MapContainer>

      {/* Map Header Floating Overlay */}
      <div className="absolute top-3 left-3 z-[400] bg-slate-950/85 backdrop-blur-md border border-cyber-border rounded-lg px-3 py-2 text-xs flex items-center gap-2.5 shadow-lg">
        <Globe className="w-4 h-4 text-cyan-400 animate-pulse" />
        <div>
          <div className="font-bold text-slate-200">Reverse Hop Traversal Geotrace</div>
          <div className="text-[10px] text-slate-400">
            {geoHops.length} geolocated MTA hops | Earliest reliable origin: <span className="font-mono text-rose-400 font-bold">{geoHops[0]?.hop_ip || 'None'}</span>
          </div>
        </div>
      </div>

      {/* Map Legend Floating Overlay */}
      <div className="absolute bottom-3 right-3 z-[400] bg-slate-950/85 backdrop-blur-md border border-cyber-border rounded-lg px-2.5 py-1.5 text-[10px] flex items-center gap-3 text-slate-400 shadow-lg">
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-rose-500 ring-2 ring-rose-500/40"></span>
          <span>Origin MTA</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-amber-400"></span>
          <span>Transit Relay</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
          <span>Final MX</span>
        </div>
      </div>
    </div>
  );
}

