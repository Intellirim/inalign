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
  { timestamp: '00:00', injection_attempts: 4, pii_detections: 7, anomalies: 2 },
  { timestamp: '02:00', injection_attempts: 3, pii_detections: 5, anomalies: 1 },
  { timestamp: '04:00', injection_attempts: 6, pii_detections: 8, anomalies: 3 },
  { timestamp: '06:00', injection_attempts: 2, pii_detections: 4, anomalies: 1 },
  { timestamp: '08:00', injection_attempts: 8, pii_detections: 12, anomalies: 5 },
  { timestamp: '10:00', injection_attempts: 12, pii_detections: 15, anomalies: 4 },
  { timestamp: '12:00', injection_attempts: 9, pii_detections: 11, anomalies: 6 },
  { timestamp: '14:00', injection_attempts: 15, pii_detections: 18, anomalies: 8 },
  { timestamp: '16:00', injection_attempts: 11, pii_detections: 14, anomalies: 3 },
  { timestamp: '18:00', injection_attempts: 7, pii_detections: 9, anomalies: 2 },
  { timestamp: '20:00', injection_attempts: 5, pii_detections: 6, anomalies: 4 },
  { timestamp: '22:00', injection_attempts: 3, pii_detections: 4, anomalies: 1 },
];

interface ThreatChartProps {
  data?: TrendData[];
}

export default function ThreatChart({ data }: ThreatChartProps) {
  const chartData = data ?? sampleData;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Threats Over Time</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
              <defs>
                <linearGradient id="colorInjection" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorPII" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f97316" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorAnomaly" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#eab308" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#eab308" stopOpacity={0} />
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
                dataKey="injection_attempts"
                name="Injection"
                stroke="#ef4444"
                fill="url(#colorInjection)"
                strokeWidth={2}
              />
              <Area
                type="monotone"
                dataKey="pii_detections"
                name="PII"
                stroke="#f97316"
                fill="url(#colorPII)"
                strokeWidth={2}
              />
              <Area
                type="monotone"
                dataKey="anomalies"
                name="Anomaly"
                stroke="#eab308"
                fill="url(#colorAnomaly)"
                strokeWidth={2}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}
