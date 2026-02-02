'use client';

import React from 'react';
import { useRouter } from 'next/navigation';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '@/components/ui/Table';
import { Badge } from '@/components/ui/Badge';
import { formatDate, formatRelativeTime, cn } from '@/lib/utils';
import type { SessionResponse, RiskLevel, Severity } from '@/types';

const sampleSessions: SessionResponse[] = [
  {
    id: 'sess-001',
    agent_id: 'agent-alpha',
    status: 'active',
    risk_level: 'high',
    risk_score: 78,
    started_at: new Date(Date.now() - 3600 * 1000).toISOString(),
    last_activity: new Date(Date.now() - 120 * 1000).toISOString(),
    stats: { total_requests: 45, threats_detected: 3, threats_blocked: 2, pii_detected: 5, pii_sanitized: 5, anomalies_detected: 1, avg_risk_score: 65 },
    timeline: [],
  },
  {
    id: 'sess-002',
    agent_id: 'agent-beta',
    status: 'completed',
    risk_level: 'low',
    risk_score: 15,
    started_at: new Date(Date.now() - 7200 * 1000).toISOString(),
    last_activity: new Date(Date.now() - 3600 * 1000).toISOString(),
    ended_at: new Date(Date.now() - 3600 * 1000).toISOString(),
    stats: { total_requests: 120, threats_detected: 0, threats_blocked: 0, pii_detected: 2, pii_sanitized: 2, anomalies_detected: 0, avg_risk_score: 10 },
    timeline: [],
  },
  {
    id: 'sess-003',
    agent_id: 'agent-gamma',
    status: 'terminated',
    risk_level: 'critical',
    risk_score: 95,
    started_at: new Date(Date.now() - 10800 * 1000).toISOString(),
    last_activity: new Date(Date.now() - 7200 * 1000).toISOString(),
    ended_at: new Date(Date.now() - 7200 * 1000).toISOString(),
    stats: { total_requests: 67, threats_detected: 8, threats_blocked: 6, pii_detected: 12, pii_sanitized: 10, anomalies_detected: 4, avg_risk_score: 88 },
    timeline: [],
  },
  {
    id: 'sess-004',
    agent_id: 'agent-delta',
    status: 'active',
    risk_level: 'medium',
    risk_score: 42,
    started_at: new Date(Date.now() - 1800 * 1000).toISOString(),
    last_activity: new Date(Date.now() - 60 * 1000).toISOString(),
    stats: { total_requests: 23, threats_detected: 1, threats_blocked: 1, pii_detected: 0, pii_sanitized: 0, anomalies_detected: 1, avg_risk_score: 35 },
    timeline: [],
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
            key={session.id}
            className="cursor-pointer"
            onClick={() => router.push(`/dashboard/sessions/${session.id}`)}
          >
            <TableCell className="font-mono text-xs text-blue-400">
              {session.id}
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
                    style={{ width: `${session.risk_score}%` }}
                  />
                </div>
                <span className="text-xs text-slate-400">{session.risk_score}</span>
              </div>
            </TableCell>
            <TableCell className="text-xs">
              {session.stats.total_requests} req
            </TableCell>
            <TableCell className="text-xs">{formatDate(session.started_at)}</TableCell>
            <TableCell className="text-xs">{formatRelativeTime(session.last_activity)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
