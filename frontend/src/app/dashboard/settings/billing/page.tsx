'use client';

import React from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { formatNumber } from '@/lib/utils';

export default function BillingPage() {
  const usageStats = [
    { label: 'API Requests (this month)', value: 24853, limit: 100000 },
    { label: 'Scans Performed', value: 18420, limit: 50000 },
    { label: 'Reports Generated', value: 47, limit: 500 },
    { label: 'Active Sessions', value: 12, limit: 100 },
  ];

  return (
    <div className="space-y-6">
      {/* Current Plan */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Current Plan</CardTitle>
            <Badge variant="info">Pro</Badge>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex items-baseline gap-2">
            <span className="text-4xl font-bold text-white">$99</span>
            <span className="text-slate-400">/month</span>
          </div>
          <p className="mt-2 text-sm text-slate-400">
            Pro plan includes 100,000 API requests, 50,000 scans, 500 reports,
            and up to 100 concurrent sessions per month.
          </p>
          <div className="mt-4 flex gap-3">
            <Button variant="secondary">Change Plan</Button>
            <Button variant="ghost">View Invoice History</Button>
          </div>
        </CardContent>
      </Card>

      {/* Usage Stats */}
      <Card>
        <CardHeader>
          <CardTitle>Usage This Month</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-6">
            {usageStats.map((stat) => {
              const percentage = Math.min((stat.value / stat.limit) * 100, 100);
              const isHigh = percentage > 80;

              return (
                <div key={stat.label}>
                  <div className="mb-2 flex items-center justify-between text-sm">
                    <span className="text-slate-300">{stat.label}</span>
                    <span className="text-slate-400">
                      {formatNumber(stat.value)} / {formatNumber(stat.limit)}
                    </span>
                  </div>
                  <div className="h-2.5 overflow-hidden rounded-full bg-slate-700">
                    <div
                      className={`h-full rounded-full transition-all ${
                        isHigh ? 'bg-orange-500' : 'bg-blue-500'
                      }`}
                      style={{ width: `${percentage}%` }}
                    />
                  </div>
                  <p className="mt-1 text-right text-xs text-slate-500">
                    {percentage.toFixed(1)}% used
                  </p>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Usage Chart Placeholder */}
      <Card>
        <CardHeader>
          <CardTitle>Usage Trend</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex h-64 items-center justify-center rounded-lg border border-dashed border-slate-700 text-slate-500">
            <div className="text-center">
              <svg className="mx-auto mb-2 h-10 w-10 text-slate-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z" />
              </svg>
              <p className="text-sm">Daily usage chart will appear here</p>
              <p className="text-xs text-slate-600">Requires recharts integration</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
