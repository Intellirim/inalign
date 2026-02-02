'use client';

import React, { useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Input } from '@/components/ui/Input';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from '@/components/ui/Table';

interface Webhook {
  id: string;
  name: string;
  url: string;
  events: string[];
  is_active: boolean;
  created_at: string;
}

const EVENT_OPTIONS = [
  'alert.created',
  'alert.critical',
  'threat.detected',
  'pii.detected',
  'session.terminated',
  'report.generated',
];

export default function WebhooksPage() {
  const [webhooks, setWebhooks] = useState<Webhook[]>([
    {
      id: 'wh-1',
      name: 'Slack Alerts',
      url: 'https://hooks.slack.com/services/xxx',
      events: ['alert.created', 'alert.critical'],
      is_active: true,
      created_at: new Date(Date.now() - 86400000 * 7).toISOString(),
    },
    {
      id: 'wh-2',
      name: 'PagerDuty Critical',
      url: 'https://events.pagerduty.com/integration/xxx',
      events: ['alert.critical', 'session.terminated'],
      is_active: true,
      created_at: new Date(Date.now() - 86400000 * 3).toISOString(),
    },
  ]);

  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [selectedEvents, setSelectedEvents] = useState<string[]>([]);

  function toggleEvent(event: string) {
    setSelectedEvents((prev) =>
      prev.includes(event) ? prev.filter((e) => e !== event) : [...prev, event],
    );
  }

  function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!name || !url || selectedEvents.length === 0) return;

    const newWebhook: Webhook = {
      id: `wh-${Date.now()}`,
      name,
      url,
      events: selectedEvents,
      is_active: true,
      created_at: new Date().toISOString(),
    };
    setWebhooks((prev) => [newWebhook, ...prev]);
    setName('');
    setUrl('');
    setSelectedEvents([]);
  }

  function handleDelete(id: string) {
    setWebhooks((prev) => prev.filter((w) => w.id !== id));
  }

  return (
    <div className="space-y-6">
      {/* Add Webhook Form */}
      <Card>
        <CardHeader>
          <CardTitle>Add Webhook</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleCreate} className="space-y-4">
            <Input
              label="Webhook Name"
              placeholder="e.g., Slack Critical Alerts"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
            <Input
              label="URL"
              type="url"
              placeholder="https://hooks.example.com/webhook"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              required
            />
            <div>
              <label className="mb-2 block text-sm font-medium text-slate-300">
                Events
              </label>
              <div className="flex flex-wrap gap-2">
                {EVENT_OPTIONS.map((event) => (
                  <button
                    key={event}
                    type="button"
                    onClick={() => toggleEvent(event)}
                    className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${
                      selectedEvents.includes(event)
                        ? 'border-blue-500 bg-blue-500/20 text-blue-400'
                        : 'border-slate-700 bg-slate-800 text-slate-400 hover:border-slate-600'
                    }`}
                  >
                    {event}
                  </button>
                ))}
              </div>
            </div>
            <Button type="submit" disabled={!name || !url || selectedEvents.length === 0}>
              Add Webhook
            </Button>
          </form>
        </CardContent>
      </Card>

      {/* Webhooks List */}
      <Card>
        <CardHeader>
          <CardTitle>Configured Webhooks</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>URL</TableHead>
                <TableHead>Events</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {webhooks.map((webhook) => (
                <TableRow key={webhook.id}>
                  <TableCell className="font-medium text-slate-200">
                    {webhook.name}
                  </TableCell>
                  <TableCell className="max-w-[200px] truncate font-mono text-xs text-slate-400">
                    {webhook.url}
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {webhook.events.map((e) => (
                        <Badge key={e} variant="info">{e}</Badge>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant={webhook.is_active ? 'low' : 'critical'}>
                      {webhook.is_active ? 'Active' : 'Inactive'}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Button
                      size="sm"
                      variant="danger"
                      onClick={() => handleDelete(webhook.id)}
                    >
                      Delete
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
              {webhooks.length === 0 && (
                <TableRow>
                  <TableCell colSpan={5} className="text-center text-slate-500">
                    No webhooks configured.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
