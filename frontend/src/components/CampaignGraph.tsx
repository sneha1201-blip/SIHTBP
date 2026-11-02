'use client';

import React, { useState, useMemo } from 'react';
import { CampaignGraphData, GraphNode, GraphEdge } from '../lib/types';
import { Network, Shield, AlertTriangle, Layers, ZoomIn, ZoomOut, RotateCcw, Server, Mail, ExternalLink, Hash } from 'lucide-react';

interface CampaignGraphProps {
  graphData: CampaignGraphData;
  activeEmailId?: string;
}

export function CampaignGraph({ graphData, activeEmailId }: CampaignGraphProps) {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [filterType, setFilterType] = useState<string>('ALL');
  const [zoomLevel, setZoomLevel] = useState<number>(1);

  const { nodes, edges } = graphData.graph;

  // Filter nodes according to selected category
  const filteredNodes = useMemo(() => {
    if (filterType === 'ALL') return nodes;
    return nodes.filter((n) => n.type === filterType);
  }, [nodes, filterType]);

  const filteredNodeIds = useMemo(() => new Set(filteredNodes.map((n) => n.id)), [filteredNodes]);

  // Filter edges where both source and target exist in filtered nodes
  const filteredEdges = useMemo(() => {
    return edges.filter((e) => filteredNodeIds.has(e.source) && filteredNodeIds.has(e.target));
  }, [edges, filteredNodeIds]);

  // Compute fixed 2D layout coordinates for nodes
  // Layout puts CAMPAIGN at the center, EMAIL nodes in an inner orbital ring,
  // INFRASTRUCTURE_IP and IOC nodes in an outer ring
  const nodePositions = useMemo(() => {
    const positions: Record<string, { x: number; y: number }> = {};
    const width = 800;
    const height = 440;
    const centerX = width / 2;
    const centerY = height / 2;

    const campaignNodes = nodes.filter((n) => n.type === 'CAMPAIGN');
    const emailNodes = nodes.filter((n) => n.type === 'EMAIL');
    const infraNodes = nodes.filter((n) => n.type === 'INFRASTRUCTURE_IP');
    const iocNodes = nodes.filter((n) => n.type === 'IOC');

    // 1. Center: Campaigns
    campaignNodes.forEach((node, i) => {
      const offset = (i - (campaignNodes.length - 1) / 2) * 90;
      positions[node.id] = { x: centerX + offset, y: centerY - 20 };
    });

    // 2. Inner Ring: Emails (Radius ~160px)
    const emailRadius = 150;
    emailNodes.forEach((node, i) => {
      const angle = (i / Math.max(emailNodes.length, 1)) * 2 * Math.PI - Math.PI / 2;
      positions[node.id] = {
        x: centerX + Math.cos(angle) * emailRadius,
        y: centerY + Math.sin(angle) * (emailRadius * 0.75),
      };
    });

    // 3. Outer Ring: Infrastructure & IoCs (Radius ~280px)
    const outerRadiusX = 310;
    const outerRadiusY = 180;
    const outerNodes = [...infraNodes, ...iocNodes];
    outerNodes.forEach((node, i) => {
      const angle = (i / Math.max(outerNodes.length, 1)) * 2 * Math.PI - Math.PI / 3;
      positions[node.id] = {
        x: centerX + Math.cos(angle) * outerRadiusX,
        y: centerY + Math.sin(angle) * outerRadiusY,
      };
    });

    return positions;
  }, [nodes]);

  const getNodeTheme = (type: GraphNode['type']) => {
    switch (type) {
      case 'CAMPAIGN':
        return {
          fill: '#581c87', // fuchsia-900
          stroke: '#d946ef', // fuchsia-500
          text: 'text-fuchsia-300',
          badgeBg: 'bg-fuchsia-950/80 text-fuchsia-300 border-fuchsia-700',
          icon: Shield,
        };
      case 'EMAIL':
        return {
          fill: '#7f1d1d', // rose-900
          stroke: '#f43f5e', // rose-500
          text: 'text-rose-300',
          badgeBg: 'bg-rose-950/80 text-rose-300 border-rose-700',
          icon: Mail,
        };
      case 'INFRASTRUCTURE_IP':
        return {
          fill: '#164e63', // cyan-900
          stroke: '#06b6d4', // cyan-500
          text: 'text-cyan-300',
          badgeBg: 'bg-cyan-950/80 text-cyan-300 border-cyan-700',
          icon: Server,
        };
      case 'IOC':
        return {
          fill: '#78350f', // amber-900
          stroke: '#f59e0b', // amber-500
          text: 'text-amber-300',
          badgeBg: 'bg-amber-950/80 text-amber-300 border-amber-700',
          icon: Hash,
        };
      default:
        return {
          fill: '#1e293b',
          stroke: '#64748b',
          text: 'text-slate-300',
          badgeBg: 'bg-slate-900 text-slate-300 border-slate-700',
          icon: Network,
        };
    }
  };

  return (
    <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow-xl flex flex-col gap-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
            <Network className="w-4 h-4 text-cyan-400" /> Campaign & Cross-Incident Intelligence Graph
          </h3>
          <p className="text-[11px] text-slate-400 mt-0.5">
            Clustered by shared ASN subnet, SimHash lexical fingerprint, and C2 IoC infrastructure
          </p>
        </div>

        {/* Filter Pills and Zoom Controls */}
        <div className="flex items-center gap-2">
          {/* Filter Pills */}
          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-[11px]">
            {['ALL', 'CAMPAIGN', 'EMAIL', 'INFRASTRUCTURE_IP', 'IOC'].map((t) => (
              <button
                key={t}
                onClick={() => setFilterType(t)}
                className={`px-2 py-0.5 rounded font-semibold transition ${
                  filterType === t
                    ? 'bg-cyan-600 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {t === 'INFRASTRUCTURE_IP' ? 'INFRA' : t}
              </button>
            ))}
          </div>

          {/* Zoom controls */}
          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
            <button
              onClick={() => setZoomLevel((z) => Math.min(z + 0.15, 1.6))}
              className="p-1 text-slate-400 hover:text-white"
              title="Zoom In"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setZoomLevel((z) => Math.max(z - 0.15, 0.7))}
              className="p-1 text-slate-400 hover:text-white"
              title="Zoom Out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setZoomLevel(1)}
              className="p-1 text-slate-400 hover:text-white"
              title="Reset View"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* SVG Canvas Container */}
      <div className="relative w-full h-[450px] bg-slate-950/80 rounded-xl border border-cyber-border/70 overflow-hidden flex items-center justify-center">
        {/* Subtle Cyber Grid Background */}
        <div
          className="absolute inset-0 opacity-15 pointer-events-none"
          style={{
            backgroundImage: `radial-gradient(circle at 1px 1px, #06b6d4 1px, transparent 0)`,
            backgroundSize: '24px 24px',
          }}
        />

        <svg
          viewBox="0 0 800 440"
          className="w-full h-full cursor-grab active:cursor-grabbing transition-transform duration-200 select-none"
          style={{ transform: `scale(${zoomLevel})` }}
        >
          <defs>
            {/* Glowing filter */}
            <filter id="cyber-glow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
            {/* Arrow marker */}
            <marker
              id="arrowhead"
              markerWidth="8"
              markerHeight="6"
              refX="14"
              refY="3"
              orient="auto"
            >
              <polygon points="0 0, 8 3, 0 6" fill="#38bdf8" opacity="0.75" />
            </marker>
          </defs>

          {/* Render Graph Edges */}
          {filteredEdges.map((edge) => {
            const p1 = nodePositions[edge.source];
            const p2 = nodePositions[edge.target];
            if (!p1 || !p2) return null;

            const isConnectedToSelected =
              selectedNode && (selectedNode.id === edge.source || selectedNode.id === edge.target);

            return (
              <g key={edge.id}>
                <line
                  x1={p1.x}
                  y1={p1.y}
                  x2={p2.x}
                  y2={p2.y}
                  stroke={isConnectedToSelected ? '#06b6d4' : '#334155'}
                  strokeWidth={isConnectedToSelected ? 2.5 : 1.2}
                  strokeDasharray={isConnectedToSelected ? '4 2' : 'none'}
                  strokeOpacity={isConnectedToSelected ? 0.95 : 0.6}
                  markerEnd="url(#arrowhead)"
                />
                {/* Midpoint relationship badge */}
                <text
                  x={(p1.x + p2.x) / 2}
                  y={(p1.y + p2.y) / 2 - 4}
                  fill="#94a3b8"
                  fontSize="8"
                  fontFamily="monospace"
                  textAnchor="middle"
                  className="pointer-events-none"
                >
                  {edge.relationship.replace('_', ' ')}
                </text>
              </g>
            );
          })}

          {/* Render Graph Nodes */}
          {filteredNodes.map((node) => {
            const pos = nodePositions[node.id];
            if (!pos) return null;

            const isSelected = selectedNode?.id === node.id;
            const theme = getNodeTheme(node.type);
            const isCampaign = node.type === 'CAMPAIGN';
            const radius = isCampaign ? 22 : 16;

            return (
              <g
                key={node.id}
                transform={`translate(${pos.x}, ${pos.y})`}
                onClick={() => setSelectedNode(node)}
                className="cursor-pointer group"
              >
                {/* Outer Selection / Pulse Ring */}
                {isSelected && (
                  <circle
                    r={radius + 8}
                    fill="none"
                    stroke={theme.stroke}
                    strokeWidth="2"
                    strokeDasharray="4 2"
                    className="animate-spin origin-center"
                  />
                )}

                {/* Node Body Circle */}
                <circle
                  r={radius}
                  fill={theme.fill}
                  stroke={theme.stroke}
                  strokeWidth={isSelected ? 3 : 1.8}
                  filter="url(#cyber-glow)"
                  className="transition-all duration-200 group-hover:scale-110"
                />

                {/* Node Label Text */}
                <text
                  y={radius + 14}
                  textAnchor="middle"
                  fill="#f1f5f9"
                  fontSize="10"
                  fontFamily="sans-serif"
                  fontWeight="600"
                  className="pointer-events-none shadow-sm"
                >
                  {node.label.length > 22 ? `${node.label.substring(0, 20)}…` : node.label}
                </text>

                {/* Node Subtype Subtext */}
                <text
                  y={radius + 24}
                  textAnchor="middle"
                  fill="#64748b"
                  fontSize="8"
                  fontFamily="monospace"
                  className="pointer-events-none"
                >
                  {node.type}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Selected Node Details Drawer Overlay */}
        {selectedNode && (
          <div className="absolute top-3 right-3 w-72 bg-slate-950/95 border border-cyber-border rounded-xl p-4 shadow-2xl backdrop-blur-md z-10 text-xs">
            <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800">
              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${getNodeTheme(selectedNode.type).badgeBg}`}>
                {selectedNode.type}
              </span>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-slate-400 hover:text-white text-xs font-mono"
              >
                ✕
              </button>
            </div>

            <div className="font-semibold text-white mb-2 leading-tight">
              {selectedNode.label}
            </div>

            <div className="space-y-1.5 text-[11px] text-slate-300 font-mono">
              <div className="text-slate-400 text-[10px] uppercase tracking-wider mb-1">Attributes:</div>
              {Object.entries(selectedNode.metadata).map(([key, value]) => (
                <div key={key} className="flex items-center justify-between bg-slate-900/60 px-2 py-1 rounded">
                  <span className="text-slate-400 capitalize">{key.replace('_', ' ')}:</span>
                  <span className="text-cyan-300 font-semibold">{String(value)}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Canvas Instructions Overlay */}
        <div className="absolute bottom-2 left-3 text-[10px] text-slate-500 font-mono pointer-events-none">
          Click any node to inspect incident metadata & shared campaign linkages
        </div>
      </div>
    </div>
  );
}

export default CampaignGraph;

