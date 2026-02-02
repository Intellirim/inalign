'use client';

import React, { useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';

const apiEndpoints = [
  {
    method: 'POST',
    path: '/api/v1/scan/input',
    description: 'Scan user input for threats, prompt injections, and PII before sending to an AI agent.',
    category: 'Scanning',
  },
  {
    method: 'POST',
    path: '/api/v1/scan/output',
    description: 'Scan AI agent output for PII leakage, harmful content, and policy violations.',
    category: 'Scanning',
  },
  {
    method: 'POST',
    path: '/api/v1/log/action',
    description: 'Log an agent action for anomaly detection and behavioral analysis.',
    category: 'Logging',
  },
  {
    method: 'GET',
    path: '/api/v1/sessions',
    description: 'List all monitored sessions with filtering and pagination.',
    category: 'Sessions',
  },
  {
    method: 'GET',
    path: '/api/v1/sessions/:id',
    description: 'Get detailed information about a specific session including timeline and stats.',
    category: 'Sessions',
  },
  {
    method: 'POST',
    path: '/api/v1/reports',
    description: 'Generate a security analysis report for a session.',
    category: 'Reports',
  },
  {
    method: 'GET',
    path: '/api/v1/reports/:id',
    description: 'Retrieve a generated report by ID.',
    category: 'Reports',
  },
  {
    method: 'GET',
    path: '/api/v1/alerts',
    description: 'List security alerts with filtering by severity and acknowledgement status.',
    category: 'Alerts',
  },
  {
    method: 'POST',
    path: '/api/v1/alerts/:id/acknowledge',
    description: 'Acknowledge a security alert.',
    category: 'Alerts',
  },
  {
    method: 'GET',
    path: '/api/v1/dashboard/stats',
    description: 'Get overview statistics for the dashboard.',
    category: 'Dashboard',
  },
  {
    method: 'GET',
    path: '/api/v1/dashboard/trends',
    description: 'Get threat trend data over time.',
    category: 'Dashboard',
  },
  {
    method: 'POST',
    path: '/api/v1/auth/login',
    description: 'Authenticate and receive a JWT access token.',
    category: 'Authentication',
  },
];

function methodColor(method: string): string {
  switch (method) {
    case 'GET':
      return 'text-green-400 bg-green-400/10';
    case 'POST':
      return 'text-blue-400 bg-blue-400/10';
    case 'PUT':
      return 'text-yellow-400 bg-yellow-400/10';
    case 'DELETE':
      return 'text-red-400 bg-red-400/10';
    default:
      return 'text-slate-400 bg-slate-400/10';
  }
}

export default function DocsPage() {
  const [activeCategory, setActiveCategory] = useState('');

  const categories = [...new Set(apiEndpoints.map((e) => e.category))];
  const filtered = activeCategory
    ? apiEndpoints.filter((e) => e.category === activeCategory)
    : apiEndpoints;

  return (
    <div className="space-y-6">
      {/* Intro */}
      <Card>
        <CardHeader>
          <CardTitle>AgentShield API Documentation</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-slate-400">
            The AgentShield API provides endpoints for scanning AI agent inputs and outputs,
            logging actions for anomaly detection, managing sessions, generating security reports,
            and handling alerts. All endpoints require authentication via Bearer token.
          </p>
          <div className="mt-4 rounded-lg bg-slate-700/30 p-4">
            <p className="text-sm text-slate-300">
              <span className="font-medium">Base URL:</span>{' '}
              <code className="rounded bg-slate-800 px-2 py-0.5 text-blue-400">
                https://api.agentshield.io/api/v1
              </code>
            </p>
            <p className="mt-2 text-sm text-slate-300">
              <span className="font-medium">Auth Header:</span>{' '}
              <code className="rounded bg-slate-800 px-2 py-0.5 text-blue-400">
                Authorization: Bearer &lt;your-api-key&gt;
              </code>
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Category Filter */}
      <div className="flex flex-wrap gap-2">
        <button
          onClick={() => setActiveCategory('')}
          className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${
            activeCategory === ''
              ? 'border-blue-500 bg-blue-500/20 text-blue-400'
              : 'border-slate-700 bg-slate-800 text-slate-400 hover:border-slate-600'
          }`}
        >
          All
        </button>
        {categories.map((cat) => (
          <button
            key={cat}
            onClick={() => setActiveCategory(cat)}
            className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${
              activeCategory === cat
                ? 'border-blue-500 bg-blue-500/20 text-blue-400'
                : 'border-slate-700 bg-slate-800 text-slate-400 hover:border-slate-600'
            }`}
          >
            {cat}
          </button>
        ))}
      </div>

      {/* Endpoints */}
      <div className="space-y-3">
        {filtered.map((endpoint, i) => (
          <Card key={i}>
            <CardContent className="py-4">
              <div className="flex items-start gap-3">
                <span
                  className={`inline-block rounded px-2 py-1 text-xs font-bold ${methodColor(endpoint.method)}`}
                >
                  {endpoint.method}
                </span>
                <div className="flex-1">
                  <code className="text-sm font-medium text-slate-200">
                    {endpoint.path}
                  </code>
                  <p className="mt-1 text-sm text-slate-400">
                    {endpoint.description}
                  </p>
                  <Badge variant="info" className="mt-2">
                    {endpoint.category}
                  </Badge>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
