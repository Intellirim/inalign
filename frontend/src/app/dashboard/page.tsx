'use client';

import React, { useEffect, useState } from 'react';
import StatsCards from '@/components/dashboard/StatsCards';
import ThreatChart from '@/components/dashboard/ThreatChart';
import RecentAlerts from '@/components/dashboard/RecentAlerts';
import SessionList from '@/components/sessions/SessionList';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { api } from '@/lib/api';
import type { DashboardStats, TrendData, AlertResponse, SessionResponse } from '@/types';

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | undefined>();
  const [trends, setTrends] = useState<TrendData[] | undefined>();
  const [alerts, setAlerts] = useState<AlertResponse[] | undefined>();
  const [sessions, setSessions] = useState<SessionResponse[] | undefined>();

  useEffect(() => {
    async function load() {
      try {
        const [statsRes, trendsRes, alertsRes, sessionsRes] = await Promise.allSettled([
          api.getDashboardStats(),
          api.getDashboardTrends(),
          api.getAlerts({ size: 5 }),
          api.getSessions({ size: 5 }),
        ]);
        if (statsRes.status === 'fulfilled') setStats(statsRes.value);
        if (trendsRes.status === 'fulfilled') setTrends(trendsRes.value);
        if (alertsRes.status === 'fulfilled') setAlerts(alertsRes.value.items);
        if (sessionsRes.status === 'fulfilled') setSessions(sessionsRes.value.items);
      } catch {
        // Fall back to sample data (components use defaults)
      }
    }
    load();
  }, []);

  return (
    <div className="space-y-6">
      {/* Stats row */}
      <StatsCards stats={stats} />

      {/* Threat chart (full-width) */}
      <ThreatChart data={trends} />

      {/* Two column grid: Alerts + Sessions */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <RecentAlerts alerts={alerts} />
        <Card>
          <CardHeader>
            <CardTitle>Recent Sessions</CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <SessionList sessions={sessions} />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
