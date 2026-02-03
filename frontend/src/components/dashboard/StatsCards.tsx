'use client';

import React from 'react';
import { Card, CardContent } from '@/components/ui/Card';
import { cn } from '@/lib/utils';
import { formatNumber } from '@/lib/utils';
import type { DashboardStats } from '@/types';

interface StatCardProps {
  title: string;
  value: number;
  trend: number;
  icon: React.ReactNode;
  color: string;
}

function StatCard({ title, value, trend, icon, color }: StatCardProps) {
  const isPositive = trend >= 0;

  return (
    <Card>
      <CardContent className="flex items-center gap-4 py-5">
        <div className={cn('flex h-12 w-12 items-center justify-center rounded-lg', color)}>
          {icon}
        </div>
        <div className="flex-1">
          <p className="text-sm text-slate-400">{title}</p>
          <div className="flex items-baseline gap-2">
            <p className="text-2xl font-bold text-white">{formatNumber(value)}</p>
            <span
              className={cn(
                'flex items-center text-xs font-medium',
                isPositive ? 'text-green-400' : 'text-red-400',
              )}
            >
              {isPositive ? (
                <svg className="mr-0.5 h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M5 15l7-7 7 7" />
                </svg>
              ) : (
                <svg className="mr-0.5 h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                </svg>
              )}
              {Math.abs(trend)}%
            </span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

interface StatsCardsProps {
  stats?: DashboardStats;
}

export default function StatsCards({ stats }: StatsCardsProps) {
  const data = stats ?? {
    total_requests: 24853,
    threats_blocked: 142,
    pii_sanitized: 387,
    active_sessions: 12,
    anomalies_detected: 8,
  };

  const cards: StatCardProps[] = [
    {
      title: 'Total Requests',
      value: data.total_requests ?? 0,
      trend: 0,
      color: 'bg-blue-500/20 text-blue-400',
      icon: (
        <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
        </svg>
      ),
    },
    {
      title: 'Threats Blocked',
      value: data.threats_blocked ?? 0,
      trend: 0,
      color: 'bg-red-500/20 text-red-400',
      icon: (
        <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
        </svg>
      ),
    },
    {
      title: 'PII Sanitized',
      value: data.pii_sanitized ?? 0,
      trend: 0,
      color: 'bg-orange-500/20 text-orange-400',
      icon: (
        <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
      ),
    },
    {
      title: 'Active Sessions',
      value: data.active_sessions ?? 0,
      trend: 0,
      color: 'bg-green-500/20 text-green-400',
      icon: (
        <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" />
        </svg>
      ),
    },
  ];

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
      {cards.map((card) => (
        <StatCard key={card.title} {...card} />
      ))}
    </div>
  );
}
