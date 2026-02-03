'use client';

import React, { useState, useEffect, useRef } from 'react';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';

interface ActivityEvent {
  id: string;
  event_type: string;
  timestamp: string;
  agent_id: string;
  session_id: string;
  data: {
    action_id?: string;
    activity_type?: string;
    name?: string;
    target?: string;
    status?: string;
    policy_result?: string;
    risk_score?: number;
    duration_ms?: number;
    threat_type?: string;
    severity?: string;
    violation_type?: string;
  };
}

export default function MonitorPage() {
  const [connected, setConnected] = useState(false);
  const [events, setEvents] = useState<ActivityEvent[]>([]);
  const [filter, setFilter] = useState<string>('all');
  const [selectedAgent, setSelectedAgent] = useState<string>('all');
  const eventsEndRef = useRef<HTMLDivElement>(null);

  // Demo data for UI preview
  useEffect(() => {
    const demoEvents: ActivityEvent[] = [
      {
        id: '1',
        event_type: 'activity',
        timestamp: new Date().toISOString(),
        agent_id: 'coding-assistant',
        session_id: 'sess-abc123',
        data: {
          action_id: 'act-001',
          activity_type: 'tool_call',
          name: 'web_search',
          target: 'google.com',
          status: 'success',
          policy_result: 'allowed',
          risk_score: 0.1,
          duration_ms: 234,
        },
      },
      {
        id: '2',
        event_type: 'activity',
        timestamp: new Date(Date.now() - 1000).toISOString(),
        agent_id: 'data-analyst',
        session_id: 'sess-def456',
        data: {
          action_id: 'act-002',
          activity_type: 'file_access',
          name: 'read',
          target: '/data/reports/q4.csv',
          status: 'success',
          policy_result: 'allowed',
          risk_score: 0.2,
          duration_ms: 45,
        },
      },
      {
        id: '3',
        event_type: 'policy_violation',
        timestamp: new Date(Date.now() - 2000).toISOString(),
        agent_id: 'coding-assistant',
        session_id: 'sess-abc123',
        data: {
          action_id: 'act-003',
          activity_type: 'file_access',
          name: 'read',
          target: '/etc/passwd',
          status: 'blocked',
          policy_result: 'denied',
          violation_type: 'permission_denied',
          severity: 'high',
        },
      },
      {
        id: '4',
        event_type: 'threat',
        timestamp: new Date(Date.now() - 3000).toISOString(),
        agent_id: 'support-bot',
        session_id: 'sess-ghi789',
        data: {
          action_id: 'act-004',
          threat_type: 'prompt_injection',
          severity: 'high',
          risk_score: 0.85,
        },
      },
      {
        id: '5',
        event_type: 'activity',
        timestamp: new Date(Date.now() - 4000).toISOString(),
        agent_id: 'data-analyst',
        session_id: 'sess-def456',
        data: {
          action_id: 'act-005',
          activity_type: 'llm_call',
          name: 'gpt-4',
          status: 'success',
          policy_result: 'allowed',
          risk_score: 0.05,
          duration_ms: 1523,
        },
      },
    ];
    setEvents(demoEvents);
  }, []);

  const getEventIcon = (eventType: string) => {
    switch (eventType) {
      case 'activity':
        return (
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-blue-500/20">
            <svg className="h-4 w-4 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          </div>
        );
      case 'threat':
        return (
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-red-500/20">
            <svg className="h-4 w-4 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
        );
      case 'policy_violation':
        return (
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-yellow-500/20">
            <svg className="h-4 w-4 text-yellow-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
            </svg>
          </div>
        );
      default:
        return (
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-slate-500/20">
            <svg className="h-4 w-4 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
        );
    }
  };

  const getStatusBadge = (status: string | undefined, policyResult: string | undefined) => {
    if (policyResult === 'denied' || status === 'blocked') {
      return <Badge variant="danger">Blocked</Badge>;
    }
    if (policyResult === 'warned') {
      return <Badge variant="warning">Warned</Badge>;
    }
    if (status === 'success') {
      return <Badge variant="success">Success</Badge>;
    }
    if (status === 'failure') {
      return <Badge variant="danger">Failed</Badge>;
    }
    return <Badge variant="default">{status || 'Unknown'}</Badge>;
  };

  const filteredEvents = events.filter((event) => {
    if (filter !== 'all' && event.event_type !== filter) return false;
    if (selectedAgent !== 'all' && event.agent_id !== selectedAgent) return false;
    return true;
  });

  const uniqueAgents = [...new Set(events.map((e) => e.agent_id))];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Real-time Monitor</h1>
          <p className="text-slate-400">Live activity stream from your AI agents</p>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={`h-2 w-2 rounded-full ${connected ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`}
          />
          <span className="text-sm text-slate-400">
            {connected ? 'Connected' : 'Disconnected'}
          </span>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-400">Total Events</p>
              <p className="mt-1 text-2xl font-bold text-white">{events.length}</p>
            </div>
            <div className="rounded-lg bg-blue-500/20 p-3">
              <svg className="h-6 w-6 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
            </div>
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-400">Threats</p>
              <p className="mt-1 text-2xl font-bold text-red-400">
                {events.filter((e) => e.event_type === 'threat').length}
              </p>
            </div>
            <div className="rounded-lg bg-red-500/20 p-3">
              <svg className="h-6 w-6 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-400">Violations</p>
              <p className="mt-1 text-2xl font-bold text-yellow-400">
                {events.filter((e) => e.event_type === 'policy_violation').length}
              </p>
            </div>
            <div className="rounded-lg bg-yellow-500/20 p-3">
              <svg className="h-6 w-6 text-yellow-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
              </svg>
            </div>
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-slate-400">Active Agents</p>
              <p className="mt-1 text-2xl font-bold text-green-400">{uniqueAgents.length}</p>
            </div>
            <div className="rounded-lg bg-green-500/20 p-3">
              <svg className="h-6 w-6 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
              </svg>
            </div>
          </div>
        </Card>
      </div>

      {/* Filters */}
      <Card className="p-4">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2">
            <span className="text-sm text-slate-400">Event Type:</span>
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-white"
            >
              <option value="all">All Events</option>
              <option value="activity">Activities</option>
              <option value="threat">Threats</option>
              <option value="policy_violation">Policy Violations</option>
            </select>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-sm text-slate-400">Agent:</span>
            <select
              value={selectedAgent}
              onChange={(e) => setSelectedAgent(e.target.value)}
              className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-white"
            >
              <option value="all">All Agents</option>
              {uniqueAgents.map((agent) => (
                <option key={agent} value={agent}>
                  {agent}
                </option>
              ))}
            </select>
          </div>
          <Button variant="outline" size="sm" onClick={() => setEvents([])}>
            Clear
          </Button>
        </div>
      </Card>

      {/* Event Stream */}
      <Card className="overflow-hidden">
        <div className="border-b border-slate-700 px-4 py-3">
          <h2 className="font-semibold text-white">Activity Stream</h2>
        </div>
        <div className="max-h-[600px] overflow-y-auto">
          {filteredEvents.length === 0 ? (
            <div className="p-8 text-center text-slate-400">
              <p>No events to display</p>
              <p className="mt-1 text-sm">Events will appear here in real-time</p>
            </div>
          ) : (
            <div className="divide-y divide-slate-700">
              {filteredEvents.map((event) => (
                <div
                  key={event.id}
                  className="flex items-start gap-4 p-4 transition-colors hover:bg-slate-800/50"
                >
                  {getEventIcon(event.event_type)}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-white">
                        {event.data.name || event.data.threat_type || event.data.violation_type}
                      </span>
                      {getStatusBadge(event.data.status, event.data.policy_result)}
                      {event.data.risk_score !== undefined && event.data.risk_score > 0.5 && (
                        <Badge variant="danger">Risk: {(event.data.risk_score * 100).toFixed(0)}%</Badge>
                      )}
                    </div>
                    <div className="mt-1 flex items-center gap-3 text-sm text-slate-400">
                      <span>{event.agent_id}</span>
                      <span>•</span>
                      <span>{event.data.activity_type || event.event_type}</span>
                      {event.data.target && (
                        <>
                          <span>•</span>
                          <span className="truncate max-w-[200px]">{event.data.target}</span>
                        </>
                      )}
                      {event.data.duration_ms && (
                        <>
                          <span>•</span>
                          <span>{event.data.duration_ms}ms</span>
                        </>
                      )}
                    </div>
                  </div>
                  <div className="text-right text-sm text-slate-400">
                    {new Date(event.timestamp).toLocaleTimeString()}
                  </div>
                </div>
              ))}
            </div>
          )}
          <div ref={eventsEndRef} />
        </div>
      </Card>
    </div>
  );
}
