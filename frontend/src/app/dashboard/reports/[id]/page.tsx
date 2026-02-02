'use client';

import React, { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import ReportDetail from '@/components/reports/ReportDetail';
import { Spinner } from '@/components/ui/Spinner';
import { api } from '@/lib/api';
import type { ReportResponse } from '@/types';

export default function ReportDetailPage() {
  const params = useParams();
  const router = useRouter();
  const id = params.id as string;

  const [report, setReport] = useState<ReportResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    async function load() {
      try {
        const res = await api.getReport(id);
        setReport(res);
      } catch {
        setError('Failed to load report.');
      } finally {
        setLoading(false);
      }
    }
    if (id) load();
  }, [id]);

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Spinner size={32} className="text-blue-400" />
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="flex h-64 flex-col items-center justify-center gap-4 text-slate-400">
        <p>{error || 'Report not found.'}</p>
        <button
          onClick={() => router.push('/dashboard/reports')}
          className="text-sm text-blue-400 hover:text-blue-300"
        >
          Back to Reports
        </button>
      </div>
    );
  }

  return <ReportDetail report={report} />;
}
