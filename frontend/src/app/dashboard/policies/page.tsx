'use client';

import React, { useState, useEffect } from 'react';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { Spinner } from '@/components/ui/Spinner';

interface Policy {
  id: string;
  name: string;
  description: string;
  agent_id: string | null;
  priority: number;
  enabled: boolean;
  policy_type: string;
  rules: {
    permissions?: {
      tools?: string[];
      apis?: string[];
      files?: string[];
    };
    denials?: {
      tools?: string[];
      apis?: string[];
      files?: string[];
      keywords?: string[];
    };
    limits?: {
      max_api_calls_per_minute?: number;
      max_cost_per_session_usd?: number;
    };
  };
  violation_count: number;
  created_at: string;
}

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);

  useEffect(() => {
    fetchPolicies();
  }, []);

  const fetchPolicies = async () => {
    // Demo data
    setPolicies([
      {
        id: '1',
        name: 'Default Security Policy',
        description: 'Base security policy for all agents',
        agent_id: null,
        priority: 1,
        enabled: true,
        policy_type: 'builtin',
        rules: {
          denials: {
            files: ['/etc/*', '~/.ssh/*', '*.env'],
            keywords: ['password', 'secret', 'api_key'],
          },
          limits: {
            max_api_calls_per_minute: 100,
            max_cost_per_session_usd: 10,
          },
        },
        violation_count: 12,
        created_at: '2024-01-01T00:00:00Z',
      },
      {
        id: '2',
        name: 'Coding Assistant Policy',
        description: 'Custom policy for the coding assistant agent',
        agent_id: 'coding-assistant',
        priority: 10,
        enabled: true,
        policy_type: 'custom',
        rules: {
          permissions: {
            tools: ['web_search', 'code_executor', 'file_reader'],
            apis: ['https://api.github.com/*'],
          },
          denials: {
            apis: ['https://api.payment.com/*'],
          },
          limits: {
            max_api_calls_per_minute: 50,
            max_cost_per_session_usd: 5,
          },
        },
        violation_count: 3,
        created_at: '2024-01-15T10:00:00Z',
      },
      {
        id: '3',
        name: 'Data Access Restriction',
        description: 'Restricts access to sensitive data directories',
        agent_id: 'data-analyst',
        priority: 5,
        enabled: true,
        policy_type: 'custom',
        rules: {
          permissions: {
            files: ['/data/public/*', '/data/reports/*'],
          },
          denials: {
            files: ['/data/private/*', '/data/pii/*'],
          },
        },
        violation_count: 7,
        created_at: '2024-01-10T08:00:00Z',
      },
      {
        id: '4',
        name: 'Payment Confirmation Rule',
        description: 'Requires user confirmation for payment-related actions',
        agent_id: null,
        priority: 2,
        enabled: false,
        policy_type: 'custom',
        rules: {
          denials: {
            keywords: ['payment', 'transaction', 'purchase'],
          },
        },
        violation_count: 0,
        created_at: '2024-01-20T12:00:00Z',
      },
    ]);
    setLoading(false);
  };

  const togglePolicy = async (policyId: string) => {
    setPolicies((prev) =>
      prev.map((p) => (p.id === policyId ? { ...p, enabled: !p.enabled } : p))
    );
  };

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center">
        <Spinner size="lg" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Policies</h1>
          <p className="text-slate-400">Define and manage agent permissions and rules</p>
        </div>
        <Button onClick={() => setShowCreateModal(true)}>+ Create Policy</Button>
      </div>

      {/* Stats */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card className="p-4">
          <div className="text-sm text-slate-400">Total Policies</div>
          <div className="mt-1 text-2xl font-bold text-white">{policies.length}</div>
        </Card>
        <Card className="p-4">
          <div className="text-sm text-slate-400">Active</div>
          <div className="mt-1 text-2xl font-bold text-green-400">
            {policies.filter((p) => p.enabled).length}
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-sm text-slate-400">Global Policies</div>
          <div className="mt-1 text-2xl font-bold text-blue-400">
            {policies.filter((p) => !p.agent_id).length}
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-sm text-slate-400">Total Violations</div>
          <div className="mt-1 text-2xl font-bold text-red-400">
            {policies.reduce((sum, p) => sum + p.violation_count, 0)}
          </div>
        </Card>
      </div>

      {/* Policy List */}
      <div className="space-y-4">
        {policies.map((policy) => (
          <Card key={policy.id} className="p-5">
            <div className="flex items-start justify-between">
              <div className="flex items-start gap-4">
                <div
                  className={`flex h-10 w-10 items-center justify-center rounded-lg ${
                    policy.enabled ? 'bg-green-500/20' : 'bg-slate-500/20'
                  }`}
                >
                  <svg
                    className={`h-5 w-5 ${policy.enabled ? 'text-green-400' : 'text-slate-400'}`}
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                    strokeWidth={2}
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                    />
                  </svg>
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="font-semibold text-white">{policy.name}</h3>
                    <Badge variant={policy.enabled ? 'success' : 'default'}>
                      {policy.enabled ? 'Active' : 'Disabled'}
                    </Badge>
                    {policy.policy_type === 'builtin' && (
                      <Badge variant="info">Built-in</Badge>
                    )}
                  </div>
                  <p className="mt-1 text-sm text-slate-400">{policy.description}</p>
                  <div className="mt-2 flex items-center gap-4 text-sm">
                    <span className="text-slate-400">
                      Priority: <span className="text-white">{policy.priority}</span>
                    </span>
                    <span className="text-slate-400">
                      Scope:{' '}
                      <span className="text-white">
                        {policy.agent_id || 'All Agents'}
                      </span>
                    </span>
                    <span className="text-slate-400">
                      Violations:{' '}
                      <span className={policy.violation_count > 0 ? 'text-red-400' : 'text-white'}>
                        {policy.violation_count}
                      </span>
                    </span>
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => togglePolicy(policy.id)}
                >
                  {policy.enabled ? 'Disable' : 'Enable'}
                </Button>
                <Button variant="outline" size="sm">
                  Edit
                </Button>
              </div>
            </div>

            {/* Rules Preview */}
            <div className="mt-4 grid gap-4 border-t border-slate-700 pt-4 sm:grid-cols-3">
              {/* Permissions */}
              {policy.rules.permissions && (
                <div>
                  <h4 className="text-sm font-medium text-green-400">Permissions</h4>
                  <ul className="mt-2 space-y-1 text-sm text-slate-400">
                    {policy.rules.permissions.tools && (
                      <li>Tools: {policy.rules.permissions.tools.join(', ')}</li>
                    )}
                    {policy.rules.permissions.apis && (
                      <li>APIs: {policy.rules.permissions.apis.length} allowed</li>
                    )}
                    {policy.rules.permissions.files && (
                      <li>Files: {policy.rules.permissions.files.length} paths</li>
                    )}
                  </ul>
                </div>
              )}

              {/* Denials */}
              {policy.rules.denials && (
                <div>
                  <h4 className="text-sm font-medium text-red-400">Denials</h4>
                  <ul className="mt-2 space-y-1 text-sm text-slate-400">
                    {policy.rules.denials.files && (
                      <li>Files: {policy.rules.denials.files.length} blocked</li>
                    )}
                    {policy.rules.denials.keywords && (
                      <li>Keywords: {policy.rules.denials.keywords.join(', ')}</li>
                    )}
                    {policy.rules.denials.apis && (
                      <li>APIs: {policy.rules.denials.apis.length} blocked</li>
                    )}
                  </ul>
                </div>
              )}

              {/* Limits */}
              {policy.rules.limits && (
                <div>
                  <h4 className="text-sm font-medium text-yellow-400">Limits</h4>
                  <ul className="mt-2 space-y-1 text-sm text-slate-400">
                    {policy.rules.limits.max_api_calls_per_minute && (
                      <li>API calls: {policy.rules.limits.max_api_calls_per_minute}/min</li>
                    )}
                    {policy.rules.limits.max_cost_per_session_usd && (
                      <li>Cost: ${policy.rules.limits.max_cost_per_session_usd}/session</li>
                    )}
                  </ul>
                </div>
              )}
            </div>
          </Card>
        ))}
      </div>

      {/* Empty State */}
      {policies.length === 0 && (
        <Card className="p-12 text-center">
          <div className="mx-auto h-12 w-12 rounded-full bg-slate-800 p-3">
            <svg
              className="h-6 w-6 text-slate-400"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
              />
            </svg>
          </div>
          <h3 className="mt-4 text-lg font-medium text-white">No policies yet</h3>
          <p className="mt-2 text-slate-400">
            Create policies to control what your AI agents can do.
          </p>
          <Button className="mt-4" onClick={() => setShowCreateModal(true)}>
            Create Policy
          </Button>
        </Card>
      )}
    </div>
  );
}
