'use client';

import React from 'react';
import Link from 'next/link';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';

const settingsCards = [
  {
    title: 'API Keys',
    description: 'Create and manage API keys for authenticating with InALign.',
    href: '/dashboard/settings/api-keys',
    icon: (
      <svg className="h-8 w-8 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
      </svg>
    ),
  },
  {
    title: 'Webhooks',
    description: 'Configure webhooks to receive real-time notifications for security events.',
    href: '/dashboard/settings/webhooks',
    icon: (
      <svg className="h-8 w-8 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
      </svg>
    ),
  },
  {
    title: 'Billing & Usage',
    description: 'View usage statistics, current plan details, and manage billing.',
    href: '/dashboard/settings/billing',
    icon: (
      <svg className="h-8 w-8 text-orange-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" />
      </svg>
    ),
  },
];

export default function SettingsPage() {
  return (
    <div className="grid grid-cols-1 gap-6 md:grid-cols-2 xl:grid-cols-3">
      {settingsCards.map((card) => (
        <Link key={card.href} href={card.href}>
          <Card className="h-full transition-colors hover:border-slate-600">
            <CardHeader>
              <div className="mb-2">{card.icon}</div>
              <CardTitle>{card.title}</CardTitle>
            </CardHeader>
            <CardContent className="pt-0">
              <p className="text-sm text-slate-400">{card.description}</p>
            </CardContent>
          </Card>
        </Link>
      ))}
    </div>
  );
}
