'use client';

import React, { useEffect, useState } from 'react';
import SessionList from '@/components/sessions/SessionList';
import { Card, CardContent } from '@/components/ui/Card';
import { api } from '@/lib/api';
import type { SessionResponse } from '@/types';

export default function SessionsPage() {
  const [sessions, setSessions] = useState<SessionResponse[] | undefined>();
  const [statusFilter, setStatusFilter] = useState('');
  const [riskFilter, setRiskFilter] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    async function load() {
      setLoading(true);
      try {
        const params: Record<string, string | number | undefined> = {
          page_size: 50,
        };
        if (statusFilter) params.status = statusFilter;
        if (riskFilter) params.risk_level = riskFilter;
        const res = await api.getSessions(params);
        setSessions(res.sessions);
      } catch {
        // Use sample data from component
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [statusFilter, riskFilter]);

  return (
    <div className="space-y-6">
      {/* Filters Bar */}
      <Card>
        <CardContent className="flex flex-wrap items-center gap-4 py-4">
          <div className="flex items-center gap-2">
            <label className="text-sm text-slate-400">Status:</label>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="h-9 rounded-lg border border-slate-700 bg-slate-800 px-3 text-sm text-slate-100 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            >
              <option value="">All</option>
              <option value="active">Active</option>
              <option value="completed">Completed</option>
              <option value="terminated">Terminated</option>
            </select>
          </div>
          <div className="flex items-center gap-2">
            <label className="text-sm text-slate-400">Risk Level:</label>
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="h-9 rounded-lg border border-slate-700 bg-slate-800 px-3 text-sm text-slate-100 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            >
              <option value="">All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="none">None</option>
            </select>
          </div>
          <div className="flex items-center gap-2">
            <label className="text-sm text-slate-400">Date:</label>
            <input
              type="date"
              className="h-9 rounded-lg border border-slate-700 bg-slate-800 px-3 text-sm text-slate-100 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>
          {loading && (
            <span className="text-xs text-slate-500">Loading...</span>
          )}
        </CardContent>
      </Card>

      {/* Sessions Table */}
      <Card>
        <CardContent className="py-4">
          <SessionList sessions={sessions} />
        </CardContent>
      </Card>
    </div>
  );
}
