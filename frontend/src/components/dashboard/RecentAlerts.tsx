'use client';

import React from 'react';
import Link from 'next/link';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { formatRelativeTime } from '@/lib/utils';
import type { AlertResponse, Severity } from '@/types';

const sampleAlerts: AlertResponse[] = [
  {
    id: 'alert-1',
    session_id: 'sess-001',
    agent_id: 'agent-alpha',
    severity: 'critical',
    title: 'Prompt injection detected in user input',
    description: 'Malicious prompt injection attempt targeting system prompt override.',
    threat_type: 'prompt_injection',
    created_at: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
    acknowledged: false,
  },
  {
    id: 'alert-2',
    session_id: 'sess-002',
    agent_id: 'agent-beta',
    severity: 'high',
    title: 'PII leakage in agent output',
    description: 'Social security number found in unfiltered output.',
    threat_type: 'pii_leakage',
    created_at: new Date(Date.now() - 23 * 60 * 1000).toISOString(),
    acknowledged: false,
  },
  {
    id: 'alert-3',
    session_id: 'sess-003',
    agent_id: 'agent-gamma',
    severity: 'medium',
    title: 'Anomalous action frequency spike',
    description: 'Agent performed 15x normal API call rate.',
    threat_type: 'anomaly',
    created_at: new Date(Date.now() - 2 * 3600 * 1000).toISOString(),
    acknowledged: true,
  },
  {
    id: 'alert-4',
    session_id: 'sess-004',
    agent_id: 'agent-delta',
    severity: 'low',
    title: 'Unusual tool usage pattern',
    description: 'Agent accessed file system tool outside normal scope.',
    threat_type: 'behavior_anomaly',
    created_at: new Date(Date.now() - 5 * 3600 * 1000).toISOString(),
    acknowledged: false,
  },
  {
    id: 'alert-5',
    session_id: 'sess-005',
    agent_id: 'agent-epsilon',
    severity: 'info',
    title: 'New session from unknown agent',
    description: 'Unregistered agent ID initiated a session.',
    threat_type: 'unknown_agent',
    created_at: new Date(Date.now() - 12 * 3600 * 1000).toISOString(),
    acknowledged: true,
  },
];

interface RecentAlertsProps {
  alerts?: AlertResponse[];
}

export default function RecentAlerts({ alerts }: RecentAlertsProps) {
  const data = alerts ?? sampleAlerts;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle>Recent Alerts</CardTitle>
        <Link
          href="/dashboard/alerts"
          className="text-sm text-blue-400 hover:text-blue-300"
        >
          View All
        </Link>
      </CardHeader>
      <CardContent className="space-y-3 pt-0">
        {data.slice(0, 5).map((alert) => (
          <div
            key={alert.id}
            className="flex items-start justify-between rounded-lg border border-slate-700/50 px-4 py-3"
          >
            <div className="flex items-start gap-3">
              <Badge variant={alert.severity as Severity}>{alert.severity}</Badge>
              <div>
                <p className="text-sm font-medium text-slate-200">{alert.title}</p>
                <p className="text-xs text-slate-500">{alert.agent_id}</p>
              </div>
            </div>
            <span className="shrink-0 text-xs text-slate-500">
              {formatRelativeTime(alert.created_at)}
            </span>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
