'use client';

import React, { useEffect, useState, useCallback } from 'react';
import { Card, CardContent } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from '@/components/ui/Table';
import { formatDate, formatRelativeTime } from '@/lib/utils';
import { api } from '@/lib/api';
import type { AlertResponse, Severity } from '@/types';

const sampleAlerts: AlertResponse[] = [
  {
    id: 'alert-1',
    session_id: 'sess-001',
    agent_id: 'agent-alpha',
    severity: 'critical',
    title: 'Prompt injection detected',
    description: 'System prompt override attempt.',
    alert_type: 'prompt_injection',
    created_at: new Date(Date.now() - 5 * 60000).toISOString(),
    is_acknowledged: false,
  },
  {
    id: 'alert-2',
    session_id: 'sess-002',
    agent_id: 'agent-beta',
    severity: 'high',
    title: 'PII leakage in agent output',
    description: 'SSN found in unfiltered output.',
    alert_type: 'pii_leakage',
    created_at: new Date(Date.now() - 23 * 60000).toISOString(),
    is_acknowledged: false,
  },
  {
    id: 'alert-3',
    session_id: 'sess-003',
    agent_id: 'agent-gamma',
    severity: 'medium',
    title: 'Anomalous API call frequency',
    description: '15x normal request rate detected.',
    alert_type: 'anomaly',
    created_at: new Date(Date.now() - 2 * 3600000).toISOString(),
    is_acknowledged: true,
    acknowledged_at: new Date(Date.now() - 3600000).toISOString(),
    acknowledged_by: 'admin',
  },
  {
    id: 'alert-4',
    session_id: 'sess-004',
    agent_id: 'agent-delta',
    severity: 'low',
    title: 'Unusual tool usage',
    description: 'File system access outside scope.',
    alert_type: 'behavior_anomaly',
    created_at: new Date(Date.now() - 5 * 3600000).toISOString(),
    is_acknowledged: false,
  },
  {
    id: 'alert-5',
    session_id: 'sess-005',
    agent_id: 'agent-epsilon',
    severity: 'info',
    title: 'New unregistered agent session',
    description: 'Unknown agent ID initiated session.',
    alert_type: 'unknown_agent',
    created_at: new Date(Date.now() - 12 * 3600000).toISOString(),
    is_acknowledged: true,
    acknowledged_at: new Date(Date.now() - 6 * 3600000).toISOString(),
    acknowledged_by: 'admin',
  },
];

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<AlertResponse[]>(sampleAlerts);
  const [severityFilter, setSeverityFilter] = useState('');
  const [acknowledgedFilter, setAcknowledgedFilter] = useState('');

  const loadAlerts = useCallback(async () => {
    try {
      const params: Record<string, string | number | boolean | undefined> = { size: 50 };
      if (severityFilter) params.severity = severityFilter;
      if (acknowledgedFilter !== '') params.acknowledged = acknowledgedFilter === 'true';
      const res = await api.getAlerts(params);
      setAlerts(res.items);
    } catch {
      // Keep sample data
    }
  }, [severityFilter, acknowledgedFilter]);

  useEffect(() => {
    loadAlerts();
  }, [loadAlerts]);

  async function handleAcknowledge(id: string) {
    try {
      await api.acknowledgeAlert(id);
      setAlerts((prev) =>
        prev.map((a) =>
          a.id === id
            ? { ...a, is_acknowledged: true, acknowledged_at: new Date().toISOString(), acknowledged_by: 'admin' }
            : a,
        ),
      );
    } catch {
      setAlerts((prev) =>
        prev.map((a) =>
          a.id === id ? { ...a, is_acknowledged: true } : a,
        ),
      );
    }
  }

  const filtered = alerts.filter((a) => {
    if (severityFilter && a.severity !== severityFilter) return false;
    if (acknowledgedFilter !== '' && String(a.is_acknowledged) !== acknowledgedFilter) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Filters */}
      <Card>
        <CardContent className="flex flex-wrap items-center gap-4 py-4">
          <div className="flex items-center gap-2">
            <label className="text-sm text-slate-400">Severity:</label>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="h-9 rounded-lg border border-slate-700 bg-slate-800 px-3 text-sm text-slate-100 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            >
              <option value="">All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>
          <div className="flex items-center gap-2">
            <label className="text-sm text-slate-400">Status:</label>
            <select
              value={acknowledgedFilter}
              onChange={(e) => setAcknowledgedFilter(e.target.value)}
              className="h-9 rounded-lg border border-slate-700 bg-slate-800 px-3 text-sm text-slate-100 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            >
              <option value="">All</option>
              <option value="false">Unacknowledged</option>
              <option value="true">Acknowledged</option>
            </select>
          </div>
        </CardContent>
      </Card>

      {/* Alerts Table */}
      <Card>
        <CardContent className="py-4">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Severity</TableHead>
                <TableHead>Title</TableHead>
                <TableHead>Agent</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((alert) => (
                <TableRow key={alert.id}>
                  <TableCell>
                    <Badge variant={alert.severity as Severity}>
                      {alert.severity}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div>
                      <p className="font-medium text-slate-200">{alert.title}</p>
                      <p className="text-xs text-slate-500">{alert.description}</p>
                    </div>
                  </TableCell>
                  <TableCell className="text-xs">{alert.agent_id}</TableCell>
                  <TableCell className="text-xs">{alert.alert_type}</TableCell>
                  <TableCell className="text-xs">
                    {formatRelativeTime(alert.created_at)}
                  </TableCell>
                  <TableCell>
                    {alert.is_acknowledged ? (
                      <span className="text-xs text-green-400">Acknowledged</span>
                    ) : (
                      <span className="text-xs text-yellow-400">Pending</span>
                    )}
                  </TableCell>
                  <TableCell>
                    {!alert.is_acknowledged && (
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => handleAcknowledge(alert.id)}
                      >
                        Acknowledge
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
              {filtered.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-slate-500">
                    No alerts found.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
