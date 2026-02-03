'use client';

import React from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { formatDate, formatRelativeTime, riskLevelColor, cn } from '@/lib/utils';
import type { SessionResponse, Severity, RiskLevel } from '@/types';

interface SessionDetailProps {
  session: SessionResponse;
  onGenerateReport?: () => void;
}

export default function SessionDetail({ session, onGenerateReport }: SessionDetailProps) {
  const { stats, timeline } = session;

  return (
    <div className="space-y-6">
      {/* Info cards row */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardContent className="py-4">
            <p className="text-sm text-slate-400">Session ID</p>
            <p className="font-mono text-sm text-blue-400">{session.session_id}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="py-4">
            <p className="text-sm text-slate-400">Agent</p>
            <p className="text-sm font-medium text-white">{session.agent_id}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="py-4">
            <p className="text-sm text-slate-400">Status</p>
            <Badge
              variant={
                session.status === 'active'
                  ? 'info'
                  : session.status === 'completed'
                    ? 'low'
                    : 'critical'
              }
            >
              {session.status}
            </Badge>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="py-4">
            <p className="text-sm text-slate-400">Risk Level</p>
            <span className={cn('text-sm font-semibold capitalize', riskLevelColor(session.risk_level))}>
              {session.risk_level} ({Math.round(session.risk_score * 100)}%)
            </span>
          </CardContent>
        </Card>
      </div>

      {/* Stats grid */}
      <Card>
        <CardHeader>
          <CardTitle>Statistics</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-4">
            {[
              { label: 'Total Actions', value: stats.total_actions },
              { label: 'Input Scans', value: stats.input_scans },
              { label: 'Output Scans', value: stats.output_scans },
              { label: 'Threats Detected', value: stats.threats_detected },
              { label: 'PII Detected', value: stats.pii_detected },
              { label: 'Anomalies', value: stats.anomalies_detected },
            ].map(({ label, value }) => (
              <div key={label} className="rounded-lg bg-slate-700/30 px-4 py-3">
                <p className="text-xs text-slate-400">{label}</p>
                <p className="text-xl font-bold text-white">{value}</p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Timeline */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle>Event Timeline</CardTitle>
          <span className="text-xs text-slate-400">
            Started {formatDate(session.started_at)}
          </span>
        </CardHeader>
        <CardContent>
          {timeline.length === 0 ? (
            <p className="text-sm text-slate-500">No events recorded yet.</p>
          ) : (
            <div className="relative space-y-0 border-l-2 border-slate-700 pl-6">
              {timeline.map((event, idx) => (
                <div key={idx} className="relative pb-6 last:pb-0">
                  {/* Dot */}
                  <div
                    className={cn(
                      'absolute -left-[31px] top-1 h-3 w-3 rounded-full border-2 border-slate-800',
                      event.severity === 'critical'
                        ? 'bg-red-500'
                        : event.severity === 'high'
                          ? 'bg-orange-500'
                          : event.severity === 'medium'
                            ? 'bg-yellow-500'
                            : 'bg-green-500',
                    )}
                  />
                  <div className="flex items-start justify-between">
                    <div>
                      <p className="text-sm font-medium text-slate-200">
                        {event.description}
                      </p>
                      <div className="mt-1 flex items-center gap-2">
                        <Badge variant={event.severity as Severity}>
                          {event.severity}
                        </Badge>
                        <span className="text-xs text-slate-500">{event.type}</span>
                      </div>
                    </div>
                    <span className="shrink-0 text-xs text-slate-500">
                      {formatRelativeTime(event.timestamp)}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Generate Report button */}
      <div className="flex justify-end">
        <Button onClick={onGenerateReport} size="lg">
          Generate Report
        </Button>
      </div>
    </div>
  );
}
