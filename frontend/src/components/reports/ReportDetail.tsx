'use client';

import React from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { cn, riskLevelColor, formatDate } from '@/lib/utils';
import type { ReportResponse, Severity } from '@/types';

interface ReportDetailProps {
  report: ReportResponse;
}

export default function ReportDetail({ report }: ReportDetailProps) {
  const { summary, analysis } = report;

  return (
    <div className="space-y-6">
      {/* Summary Section */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Report Summary</CardTitle>
            <Badge variant={summary.overall_risk as Severity}>
              {summary.overall_risk}
            </Badge>
          </div>
        </CardHeader>
        <CardContent>
          <div className="mb-4 grid grid-cols-2 gap-4 sm:grid-cols-4">
            <div className="rounded-lg bg-slate-700/30 px-4 py-3">
              <p className="text-xs text-slate-400">Risk Score</p>
              <p className={cn('text-xl font-bold', riskLevelColor(summary.overall_risk))}>
                {summary.risk_score}/100
              </p>
            </div>
            <div className="rounded-lg bg-slate-700/30 px-4 py-3">
              <p className="text-xs text-slate-400">Total Events</p>
              <p className="text-xl font-bold text-white">{summary.total_events}</p>
            </div>
            <div className="rounded-lg bg-slate-700/30 px-4 py-3">
              <p className="text-xs text-slate-400">Threats Found</p>
              <p className="text-xl font-bold text-red-400">{summary.threats_found}</p>
            </div>
            <div className="rounded-lg bg-slate-700/30 px-4 py-3">
              <p className="text-xs text-slate-400">PII Exposures</p>
              <p className="text-xl font-bold text-orange-400">{summary.pii_exposures}</p>
            </div>
          </div>

          {summary.primary_concerns.length > 0 && (
            <div>
              <h4 className="mb-2 text-sm font-medium text-slate-300">Primary Concerns</h4>
              <ul className="space-y-1">
                {summary.primary_concerns.map((concern, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                    <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-orange-400" />
                    {concern}
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="mt-4">
            <p className="text-xs text-slate-500">
              Session: <span className="font-mono text-slate-400">{report.session_id}</span>
              {' | '}
              Generated: {formatDate(report.generated_at)}
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Attack Vectors */}
      {analysis.attack_vectors.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Attack Vectors</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {analysis.attack_vectors.map((vector, i) => (
              <div key={i} className="rounded-lg border border-slate-700 p-4">
                <div className="mb-2 flex items-center justify-between">
                  <h4 className="font-medium text-slate-200">{vector.name}</h4>
                  <Badge variant={vector.severity as Severity}>{vector.severity}</Badge>
                </div>
                <p className="mb-3 text-sm text-slate-400">{vector.description}</p>
                {vector.mitre_mapping && (
                  <p className="mb-2 text-xs text-slate-500">
                    MITRE ATT&CK: <span className="font-mono text-slate-400">{vector.mitre_mapping}</span>
                  </p>
                )}
                {vector.evidence.length > 0 && (
                  <div>
                    <p className="mb-1 text-xs font-medium text-slate-400">Evidence</p>
                    <ul className="space-y-1">
                      {vector.evidence.map((e, j) => (
                        <li key={j} className="text-xs text-slate-400">
                          <code className="rounded bg-slate-700 px-1.5 py-0.5">{e}</code>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Behavior Analysis */}
      {analysis.behavior_patterns.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Behavior Analysis</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {analysis.behavior_patterns.map((pattern, i) => (
              <div key={i} className="flex items-start justify-between rounded-lg border border-slate-700/50 p-4">
                <div>
                  <p className="font-medium text-slate-200">{pattern.pattern}</p>
                  <p className="mt-1 text-sm text-slate-400">{pattern.description}</p>
                  <p className="mt-1 text-xs text-slate-500">
                    Frequency: {pattern.frequency}x | First seen: {formatDate(pattern.first_seen)}
                  </p>
                </div>
                <Badge variant={pattern.risk_level as Severity}>{pattern.risk_level}</Badge>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Timeline Summary */}
      {analysis.timeline_summary && (
        <Card>
          <CardHeader>
            <CardTitle>Timeline Summary</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="whitespace-pre-wrap text-sm leading-relaxed text-slate-300">
              {analysis.timeline_summary}
            </p>
          </CardContent>
        </Card>
      )}

      {/* Recommendations */}
      {analysis.recommendations.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Recommendations</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {analysis.recommendations.map((rec) => (
              <div
                key={rec.id}
                className={cn(
                  'flex items-start gap-3 rounded-lg border border-slate-700/50 p-4',
                  rec.implemented && 'opacity-60',
                )}
              >
                {/* Checkbox */}
                <div
                  className={cn(
                    'mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded border',
                    rec.implemented
                      ? 'border-green-500 bg-green-500/20 text-green-400'
                      : 'border-slate-600',
                  )}
                >
                  {rec.implemented && (
                    <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                    </svg>
                  )}
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <p className={cn('font-medium text-slate-200', rec.implemented && 'line-through')}>
                      {rec.title}
                    </p>
                    <Badge variant={rec.priority as Severity}>{rec.priority}</Badge>
                  </div>
                  <p className="mt-1 text-sm text-slate-400">{rec.description}</p>
                  <p className="mt-1 text-xs text-slate-500">Category: {rec.category}</p>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
