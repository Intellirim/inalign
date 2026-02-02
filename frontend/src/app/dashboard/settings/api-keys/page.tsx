'use client';

import React, { useEffect, useState } from 'react';
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
import { formatDate } from '@/lib/utils';
import { api } from '@/lib/api';
import type { APIKey } from '@/types';

const PERMISSION_OPTIONS = ['scan:read', 'scan:write', 'sessions:read', 'reports:read', 'reports:write', 'alerts:read', 'alerts:write'];

export default function APIKeysPage() {
  const [keys, setKeys] = useState<APIKey[]>([]);
  const [name, setName] = useState('');
  const [selectedPerms, setSelectedPerms] = useState<string[]>([]);
  const [createdKey, setCreatedKey] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const res = await api.getAPIKeys();
        setKeys(res);
      } catch {
        // Use empty state
      }
    }
    load();
  }, []);

  function togglePerm(perm: string) {
    setSelectedPerms((prev) =>
      prev.includes(perm) ? prev.filter((p) => p !== perm) : [...prev, perm],
    );
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!name || selectedPerms.length === 0) return;

    setLoading(true);
    try {
      const res = await api.createAPIKey({
        name,
        permissions: selectedPerms,
      });
      setCreatedKey(res.key);
      setKeys((prev) => [res, ...prev]);
      setName('');
      setSelectedPerms([]);
    } catch {
      alert('Failed to create API key.');
    } finally {
      setLoading(false);
    }
  }

  async function handleDelete(id: string) {
    if (!confirm('Are you sure you want to delete this API key?')) return;
    try {
      await api.deleteAPIKey(id);
      setKeys((prev) => prev.filter((k) => k.id !== id));
    } catch {
      alert('Failed to delete API key.');
    }
  }

  return (
    <div className="space-y-6">
      {/* Create Form */}
      <Card>
        <CardHeader>
          <CardTitle>Create API Key</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleCreate} className="space-y-4">
            <Input
              label="Key Name"
              placeholder="e.g., Production Agent Scanner"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
            <div>
              <label className="mb-2 block text-sm font-medium text-slate-300">
                Permissions
              </label>
              <div className="flex flex-wrap gap-2">
                {PERMISSION_OPTIONS.map((perm) => (
                  <button
                    key={perm}
                    type="button"
                    onClick={() => togglePerm(perm)}
                    className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${
                      selectedPerms.includes(perm)
                        ? 'border-blue-500 bg-blue-500/20 text-blue-400'
                        : 'border-slate-700 bg-slate-800 text-slate-400 hover:border-slate-600'
                    }`}
                  >
                    {perm}
                  </button>
                ))}
              </div>
            </div>
            <Button type="submit" loading={loading} disabled={!name || selectedPerms.length === 0}>
              Create Key
            </Button>
          </form>

          {createdKey && (
            <div className="mt-4 rounded-lg border border-green-500/30 bg-green-500/10 p-4">
              <p className="mb-1 text-sm font-medium text-green-400">
                API Key Created Successfully
              </p>
              <p className="text-xs text-slate-400">
                Copy this key now. You will not be able to see it again.
              </p>
              <code className="mt-2 block break-all rounded bg-slate-800 p-2 text-sm text-green-300">
                {createdKey}
              </code>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Existing Keys Table */}
      <Card>
        <CardHeader>
          <CardTitle>Existing API Keys</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Key Prefix</TableHead>
                <TableHead>Permissions</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Last Used</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {keys.map((key) => (
                <TableRow key={key.id}>
                  <TableCell className="font-medium text-slate-200">
                    {key.name}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {key.key_prefix}...
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {key.permissions.slice(0, 3).map((p) => (
                        <Badge key={p} variant="info">{p}</Badge>
                      ))}
                      {key.permissions.length > 3 && (
                        <span className="text-xs text-slate-500">
                          +{key.permissions.length - 3} more
                        </span>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="text-xs">
                    {formatDate(key.created_at)}
                  </TableCell>
                  <TableCell className="text-xs">
                    {key.last_used ? formatDate(key.last_used) : 'Never'}
                  </TableCell>
                  <TableCell>
                    <Badge variant={key.is_active ? 'low' : 'critical'}>
                      {key.is_active ? 'Active' : 'Inactive'}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Button
                      size="sm"
                      variant="danger"
                      onClick={() => handleDelete(key.id)}
                    >
                      Delete
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
              {keys.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-slate-500">
                    No API keys created yet.
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
