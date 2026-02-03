'use client';

import React, { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import SessionDetail from '@/components/sessions/SessionDetail';
import GraphViewer from '@/components/sessions/GraphViewer';
import { Spinner } from '@/components/ui/Spinner';
import { api } from '@/lib/api';
import type { SessionResponse } from '@/types';

export default function SessionDetailPage() {
  const params = useParams();
  const router = useRouter();
  const id = params.id as string;

  const [session, setSession] = useState<SessionResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    async function load() {
      try {
        const res = await api.getSession(id);
        setSession(res);
      } catch {
        setError('Failed to load session. It may not exist.');
      } finally {
        setLoading(false);
      }
    }
    if (id) load();
  }, [id]);

  async function handleGenerateReport() {
    if (!session) return;
    try {
      const report = await api.generateReport(session.session_id, {
        include_recommendations: true,
      });
      router.push(`/dashboard/reports/${report.report_id}`);
    } catch {
      alert('Failed to generate report. Please try again.');
    }
  }

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Spinner size={32} className="text-blue-400" />
      </div>
    );
  }

  if (error || !session) {
    return (
      <div className="flex h-64 flex-col items-center justify-center gap-4 text-slate-400">
        <p>{error || 'Session not found.'}</p>
        <button
          onClick={() => router.push('/dashboard/sessions')}
          className="text-sm text-blue-400 hover:text-blue-300"
        >
          Back to Sessions
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <SessionDetail session={session} onGenerateReport={handleGenerateReport} />
      <GraphViewer graph={session.graph_summary} />
    </div>
  );
}
