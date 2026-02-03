'use client';

import React from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import type { TrendData } from '@/types';

const sampleData: TrendData[] = [
  { timestamp: '00:00', count: 4 },
  { timestamp: '02:00', count: 3 },
  { timestamp: '04:00', count: 6 },
  { timestamp: '06:00', count: 2 },
  { timestamp: '08:00', count: 8 },
  { timestamp: '10:00', count: 12 },
  { timestamp: '12:00', count: 9 },
  { timestamp: '14:00', count: 15 },
  { timestamp: '16:00', count: 11 },
  { timestamp: '18:00', count: 7 },
  { timestamp: '20:00', count: 5 },
  { timestamp: '22:00', count: 3 },
];

function formatTimestamp(ts: string): string {
  if (ts.length <= 5) return ts;
  try {
    const d = new Date(ts);
    return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
  } catch {
    return ts;
  }
}

interface ThreatChartProps {
  data?: TrendData[];
}

export default function ThreatChart({ data }: ThreatChartProps) {
  const chartData = (data ?? sampleData).map((d) => ({
    ...d,
    timestamp: formatTimestamp(d.timestamp),
  }));

  return (
    <Card>
      <CardHeader>
        <CardTitle>Request Volume Over Time</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
              <defs>
                <linearGradient id="colorRequests" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis
                dataKey="timestamp"
                tick={{ fill: '#94a3b8', fontSize: 12 }}
                axisLine={{ stroke: '#334155' }}
                tickLine={{ stroke: '#334155' }}
              />
              <YAxis
                tick={{ fill: '#94a3b8', fontSize: 12 }}
                axisLine={{ stroke: '#334155' }}
                tickLine={{ stroke: '#334155' }}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1e293b',
                  border: '1px solid #334155',
                  borderRadius: '8px',
                  color: '#f1f5f9',
                }}
              />
              <Legend
                wrapperStyle={{ color: '#94a3b8', fontSize: 12 }}
              />
              <Area
                type="monotone"
                dataKey="count"
                name="Requests"
                stroke="#3b82f6"
                fill="url(#colorRequests)"
                strokeWidth={2}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}
