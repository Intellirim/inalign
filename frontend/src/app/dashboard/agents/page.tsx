'use client';

import React, { useState, useEffect } from 'react';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import { Spinner } from '@/components/ui/Spinner';

interface Agent {
  id: string;
  agent_id: string;
  name: string;
  description: string;
  framework: string;
  status: string;
  created_at: string;
  last_active_at: string | null;
}

interface AgentStats {
  agent_id: string;
  total_sessions: number;
  total_actions: number;
  total_threats: number;
  policy_violations: number;
  avg_risk_score: number;
  total_cost_usd: number;
}

export default function AgentsPage() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [stats, setStats] = useState<Record<string, AgentStats>>({});
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);

  useEffect(() => {
    fetchAgents();
  }, []);

  const fetchAgents = async () => {
    try {
      // In a real app, this would call the API
      // const response = await api.get('/api/v1/agents');
      // setAgents(response.items);

      // Demo data
      setAgents([
        {
          id: '1',
          agent_id: 'coding-assistant',
          name: 'Coding Assistant',
          description: 'AI assistant for code review and generation',
          framework: 'langchain',
          status: 'active',
          created_at: '2024-01-15T10:00:00Z',
          last_active_at: '2024-01-20T15:30:00Z',
        },
        {
          id: '2',
          agent_id: 'data-analyst',
          name: 'Data Analyst',
          description: 'Analyzes datasets and generates insights',
          framework: 'autogpt',
          status: 'active',
          created_at: '2024-01-10T08:00:00Z',
          last_active_at: '2024-01-20T14:00:00Z',
        },
        {
          id: '3',
          agent_id: 'support-bot',
          name: 'Support Bot',
          description: 'Customer support automation',
          framework: 'crewai',
          status: 'paused',
          created_at: '2024-01-05T12:00:00Z',
          last_active_at: '2024-01-18T09:00:00Z',
        },
      ]);
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch agents:', error);
      setLoading(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'success';
      case 'paused':
        return 'warning';
      case 'disabled':
        return 'danger';
      default:
        return 'default';
    }
  };

  const getFrameworkColor = (framework: string) => {
    switch (framework) {
      case 'langchain':
        return 'bg-green-500/20 text-green-400';
      case 'autogpt':
        return 'bg-purple-500/20 text-purple-400';
      case 'crewai':
        return 'bg-blue-500/20 text-blue-400';
      default:
        return 'bg-slate-500/20 text-slate-400';
    }
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
          <h1 className="text-2xl font-bold text-white">Agents</h1>
          <p className="text-slate-400">Manage and monitor your AI agents</p>
        </div>
        <Button onClick={() => setShowCreateModal(true)}>
          + Register Agent
        </Button>
      </div>

      {/* Stats Overview */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card className="p-4">
          <div className="text-sm text-slate-400">Total Agents</div>
          <div className="mt-1 text-2xl font-bold text-white">{agents.length}</div>
        </Card>
        <Card className="p-4">
          <div className="text-sm text-slate-400">Active</div>
          <div className="mt-1 text-2xl font-bold text-green-400">
            {agents.filter(a => a.status === 'active').length}
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-sm text-slate-400">Paused</div>
          <div className="mt-1 text-2xl font-bold text-yellow-400">
            {agents.filter(a => a.status === 'paused').length}
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-sm text-slate-400">Disabled</div>
          <div className="mt-1 text-2xl font-bold text-red-400">
            {agents.filter(a => a.status === 'disabled').length}
          </div>
        </Card>
      </div>

      {/* Agent List */}
      <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-3">
        {agents.map((agent) => (
          <Card key={agent.id} className="p-5">
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-blue-600/20">
                  <svg className="h-5 w-5 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                  </svg>
                </div>
                <div>
                  <h3 className="font-semibold text-white">{agent.name}</h3>
                  <p className="text-sm text-slate-400">{agent.agent_id}</p>
                </div>
              </div>
              <Badge variant={getStatusColor(agent.status)}>{agent.status}</Badge>
            </div>

            <p className="mt-3 text-sm text-slate-400 line-clamp-2">
              {agent.description || 'No description'}
            </p>

            <div className="mt-4 flex items-center gap-2">
              <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${getFrameworkColor(agent.framework)}`}>
                {agent.framework}
              </span>
            </div>

            <div className="mt-4 border-t border-slate-700 pt-4">
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-slate-400">Created</span>
                  <p className="text-white">
                    {new Date(agent.created_at).toLocaleDateString()}
                  </p>
                </div>
                <div>
                  <span className="text-slate-400">Last Active</span>
                  <p className="text-white">
                    {agent.last_active_at
                      ? new Date(agent.last_active_at).toLocaleDateString()
                      : 'Never'}
                  </p>
                </div>
              </div>
            </div>

            <div className="mt-4 flex gap-2">
              <Button variant="outline" size="sm" className="flex-1">
                View Details
              </Button>
              <Button variant="outline" size="sm" className="flex-1">
                Policies
              </Button>
            </div>
          </Card>
        ))}
      </div>

      {/* Empty State */}
      {agents.length === 0 && (
        <Card className="p-12 text-center">
          <div className="mx-auto h-12 w-12 rounded-full bg-slate-800 p-3">
            <svg className="h-6 w-6 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
          </div>
          <h3 className="mt-4 text-lg font-medium text-white">No agents yet</h3>
          <p className="mt-2 text-slate-400">
            Register your first AI agent to start monitoring and governing its actions.
          </p>
          <Button className="mt-4" onClick={() => setShowCreateModal(true)}>
            Register Agent
          </Button>
        </Card>
      )}
    </div>
  );
}
