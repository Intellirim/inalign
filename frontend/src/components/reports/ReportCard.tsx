'use client';

import React from 'react';
import Link from 'next/link';
import { Card, CardHeader, CardTitle, CardContent, CardFooter } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { formatDate } from '@/lib/utils';
import type { ReportResponse, Severity } from '@/types';

interface ReportCardProps {
  report: ReportResponse;
}

export default function ReportCard({ report }: ReportCardProps) {
  const { summary } = report;

  return (
    <Link href={`/dashboard/reports/${report.report_id}`}>
      <Card className="transition-colors hover:border-slate-600">
        <CardHeader className="flex flex-row items-start justify-between">
          <div>
            <CardTitle className="text-base">Report</CardTitle>
            <p className="mt-1 font-mono text-xs text-slate-400">{report.session_id}</p>
          </div>
          <Badge variant={summary.overall_risk as Severity}>
            {summary.overall_risk}
          </Badge>
        </CardHeader>
        <CardContent className="pt-0">
          <div className="mb-3 flex items-center gap-4 text-xs text-slate-400">
            <span>Score: {summary.risk_score}/100</span>
            <span>{summary.total_events} events</span>
            <span>{summary.threats_found} threats</span>
          </div>
          {summary.primary_concerns.length > 0 && (
            <div>
              <p className="mb-1 text-xs font-medium text-slate-400">Primary Concerns</p>
              <ul className="space-y-1">
                {summary.primary_concerns.slice(0, 3).map((concern, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                    <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-orange-400" />
                    {concern}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </CardContent>
        <CardFooter>
          <p className="text-xs text-slate-500">{formatDate(report.generated_at)}</p>
        </CardFooter>
      </Card>
    </Link>
  );
}
