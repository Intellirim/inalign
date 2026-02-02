'use client';

import React from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import type { GraphSummary } from '@/types';

interface GraphViewerProps {
  graph?: GraphSummary;
}

export default function GraphViewer({ graph }: GraphViewerProps) {
  const nodeCount = graph?.node_count ?? 8;
  const edgeCount = graph?.edge_count ?? 12;
  const hotspots = graph?.risk_hotspots ?? ['node-3', 'node-7'];

  // Generate pseudo-random node positions in a circle layout
  const nodes = Array.from({ length: nodeCount }, (_, i) => {
    const angle = (2 * Math.PI * i) / nodeCount;
    const cx = 250 + 150 * Math.cos(angle);
    const cy = 200 + 130 * Math.sin(angle);
    const isHotspot = hotspots.includes(`node-${i + 1}`) || i < hotspots.length;
    return { id: i, cx, cy, isHotspot };
  });

  // Generate edges between adjacent nodes + some cross-connections
  const edges: { from: number; to: number }[] = [];
  for (let i = 0; i < nodeCount; i++) {
    edges.push({ from: i, to: (i + 1) % nodeCount });
    if (i % 3 === 0 && i + 2 < nodeCount) {
      edges.push({ from: i, to: i + 2 });
    }
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle>Interaction Graph</CardTitle>
        <div className="flex items-center gap-4 text-xs text-slate-400">
          <span>{nodeCount} nodes</span>
          <span>{edgeCount} edges</span>
        </div>
      </CardHeader>
      <CardContent>
        <div className="flex items-center justify-center rounded-lg border border-slate-700 bg-slate-900/50 p-4">
          <svg viewBox="0 0 500 400" className="h-80 w-full max-w-lg">
            {/* Edges */}
            {edges.map((edge, i) => (
              <line
                key={`edge-${i}`}
                x1={nodes[edge.from].cx}
                y1={nodes[edge.from].cy}
                x2={nodes[edge.to].cx}
                y2={nodes[edge.to].cy}
                stroke="#334155"
                strokeWidth={1.5}
                opacity={0.6}
              />
            ))}
            {/* Nodes */}
            {nodes.map((node) => (
              <g key={`node-${node.id}`}>
                <circle
                  cx={node.cx}
                  cy={node.cy}
                  r={node.isHotspot ? 14 : 10}
                  fill={node.isHotspot ? '#ef4444' : '#3b82f6'}
                  opacity={0.8}
                  stroke={node.isHotspot ? '#fca5a5' : '#93c5fd'}
                  strokeWidth={2}
                />
                <text
                  x={node.cx}
                  y={node.cy + 4}
                  textAnchor="middle"
                  fill="#ffffff"
                  fontSize={9}
                  fontWeight={600}
                >
                  {node.id + 1}
                </text>
              </g>
            ))}
          </svg>
        </div>

        {/* Legend */}
        <div className="mt-4 flex items-center gap-6 text-xs text-slate-400">
          <div className="flex items-center gap-1.5">
            <span className="inline-block h-3 w-3 rounded-full bg-blue-500" />
            Normal Node
          </div>
          <div className="flex items-center gap-1.5">
            <span className="inline-block h-3 w-3 rounded-full bg-red-500" />
            Risk Hotspot
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
