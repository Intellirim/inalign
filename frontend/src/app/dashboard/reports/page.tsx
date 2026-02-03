'use client';

import React, { useEffect, useState } from 'react';
import ReportCard from '@/components/reports/ReportCard';
import { Spinner } from '@/components/ui/Spinner';
import { api } from '@/lib/api';
import type { ReportResponse } from '@/types';

const sampleReports: ReportResponse[] = [
  {
    report_id: 'rpt-001',
    session_id: 'sess-001',
    status: 'completed',
    generated_at: new Date(Date.now() - 3600000).toISOString(),
    summary: {
      overall_risk: 'high',
      risk_score: 78,
      total_events: 45,
      threats_found: 3,
      pii_exposures: 5,
      primary_concerns: [
        'Prompt injection attempts detected in 3 user inputs',
        'PII data (SSN, email) found in agent responses',
        'Anomalous behavior pattern in API call frequency',
      ],
    },
    analysis: {
      attack_vectors: [],
      behavior_patterns: [],
      similar_attacks: [],
      recommendations: [],
      timeline_summary: '',
    },
    recommendations: [],
  },
  {
    report_id: 'rpt-002',
    session_id: 'sess-003',
    status: 'completed',
    generated_at: new Date(Date.now() - 7200000).toISOString(),
    summary: {
      overall_risk: 'critical',
      risk_score: 95,
      total_events: 67,
      threats_found: 8,
      pii_exposures: 12,
      primary_concerns: [
        'Multiple successful prompt injection attacks',
        'Large-scale PII exfiltration attempt',
        'Agent attempted unauthorized file system access',
        'Session terminated due to risk threshold breach',
      ],
    },
    analysis: {
      attack_vectors: [],
      behavior_patterns: [],
      similar_attacks: [],
      recommendations: [],
      timeline_summary: '',
    },
    recommendations: [],
  },
  {
    report_id: 'rpt-003',
    session_id: 'sess-004',
    status: 'completed',
    generated_at: new Date(Date.now() - 86400000).toISOString(),
    summary: {
      overall_risk: 'medium',
      risk_score: 42,
      total_events: 23,
      threats_found: 1,
      pii_exposures: 0,
      primary_concerns: [
        'Single low-confidence injection attempt flagged',
        'Minor anomaly in tool usage pattern',
      ],
    },
    analysis: {
      attack_vectors: [],
      behavior_patterns: [],
      similar_attacks: [],
      recommendations: [],
      timeline_summary: '',
    },
    recommendations: [],
  },
];

export default function ReportsPage() {
  const [reports, setReports] = useState<ReportResponse[]>(sampleReports);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    async function load() {
      setLoading(true);
      try {
        const res = await api.getReports({ size: 50 });
        if (res.length > 0) setReports(res);
      } catch {
        // Keep sample data
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  if (loading && reports.length === 0) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Spinner size={32} className="text-blue-400" />
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 gap-6 md:grid-cols-2 xl:grid-cols-3">
      {reports.map((report) => (
        <ReportCard key={report.report_id} report={report} />
      ))}
      {reports.length === 0 && (
        <div className="col-span-full py-16 text-center text-slate-500">
          No reports generated yet.
        </div>
      )}
    </div>
  );
}
