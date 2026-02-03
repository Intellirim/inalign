'use client';

import React from 'react';
import { useRouter } from 'next/navigation';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/Table';
import { Badge } from '@/components/ui/Badge';
import { formatDate, formatRelativeTime, cn } from '@/lib/utils';
import type { SessionResponse, RiskLevel, Severity } from '@/types';

const sampleSessions: SessionResponse[] = [
  {
    session_id: 'sess-001',
    agent_id: 'agent-alpha',
    status: 'active',
    risk_level: 'high',
    risk_score: 0.78,
    started_at: new Date(Date.now() - 3600 * 1000).toISOString(),
    last_activity_at: new Date(Date.now() - 120 * 1000).toISOString(),
    stats: { total_actions: 45, input_scans: 20, output_scans: 25, threats_detected: 3, pii_detected: 5, anomalies_detected: 1 },
    timeline: [],
    graph_summary: { nodes: 0, edges: 0, clusters: 0 },
  },
  {
    session_id: 'sess-002',
    agent_id: 'agent-beta',
    status: 'completed',
    risk_level: 'low',
    risk_score: 0.15,
    started_at: new Date(Date.now() - 7200 * 1000).toISOString(),
    last_activity_at: new Date(Date.now() - 3600 * 1000).toISOString(),
    stats: { total_actions: 120, input_scans: 60, output_scans: 60, threats_detected: 0, pii_detected: 2, anomalies_detected: 0 },
    timeline: [],
    graph_summary: { nodes: 0, edges: 0, clusters: 0 },
  },
  {
    session_id: 'sess-003',
    agent_id: 'agent-gamma',
    status: 'terminated',
    risk_level: 'critical',
    risk_score: 0.95,
    started_at: new Date(Date.now() - 10800 * 1000).toISOString(),
    last_activity_at: new Date(Date.now() - 7200 * 1000).toISOString(),
    stats: { total_actions: 67, input_scans: 30, output_scans: 37, threats_detected: 8, pii_detected: 12, anomalies_detected: 4 },
    timeline: [],
    graph_summary: { nodes: 0, edges: 0, clusters: 0 },
  },
  {
    session_id: 'sess-004',
    agent_id: 'agent-delta',
    status: 'active',
    risk_level: 'medium',
    risk_score: 0.42,
    started_at: new Date(Date.now() - 1800 * 1000).toISOString(),
    last_activity_at: new Date(Date.now() - 60 * 1000).toISOString(),
    stats: { total_actions: 23, input_scans: 10, output_scans: 13, threats_detected: 1, pii_detected: 0, anomalies_detected: 1 },
    timeline: [],
    graph_summary: { nodes: 0, edges: 0, clusters: 0 },
  },
];

function riskBarColor(level: RiskLevel): string {
  const map: Record<RiskLevel, string> = {
    critical: 'bg-red-500',
    high: 'bg-orange-500',
    medium: 'bg-yellow-500',
    low: 'bg-green-500',
    none: 'bg-slate-500',
  };
  return map[level] ?? 'bg-slate-500';
}

function statusVariant(status: string): Severity {
  switch (status) {
    case 'active':
      return 'info';
    case 'completed':
      return 'low';
    case 'terminated':
      return 'critical';
    default:
      return 'info';
  }
}

interface SessionListProps {
  sessions?: SessionResponse[];
}

export default function SessionList({ sessions }: SessionListProps) {
  const router = useRouter();
  const data = sessions ?? sampleSessions;

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Session ID</TableHead>
          <TableHead>Agent</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Risk Score</TableHead>
          <TableHead>Actions</TableHead>
          <TableHead>Started</TableHead>
          <TableHead>Last Activity</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {data.map((session) => (
          <TableRow
            key={session.session_id}
            className="cursor-pointer"
            onClick={() => router.push(`/dashboard/sessions/${session.session_id}`)}
          >
            <TableCell className="font-mono text-xs text-blue-400">
              {session.session_id}
            </TableCell>
            <TableCell>{session.agent_id}</TableCell>
            <TableCell>
              <Badge variant={statusVariant(session.status)}>
                {session.status}
              </Badge>
            </TableCell>
            <TableCell>
              <div className="flex items-center gap-2">
                <div className="h-2 w-20 overflow-hidden rounded-full bg-slate-700">
                  <div
                    className={cn('h-full rounded-full transition-all', riskBarColor(session.risk_level))}
                    style={{ width: `${Math.round(session.risk_score * 100)}%` }}
                  />
                </div>
                <span className="text-xs text-slate-400">{Math.round(session.risk_score * 100)}</span>
              </div>
            </TableCell>
            <TableCell className="text-xs">
              {session.stats.total_actions} acts
            </TableCell>
            <TableCell className="text-xs">{formatDate(session.started_at)}</TableCell>
            <TableCell className="text-xs">{formatRelativeTime(session.last_activity_at)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
