'use client';

import React, { useState } from 'react';
import { usePathname } from 'next/navigation';
import { logout } from '@/lib/auth';

function getPageTitle(pathname: string): string {
  const map: Record<string, string> = {
    '/dashboard': 'Dashboard',
    '/dashboard/sessions': 'Sessions',
    '/dashboard/alerts': 'Alerts',
    '/dashboard/reports': 'Reports',
    '/dashboard/settings': 'Settings',
    '/dashboard/settings/api-keys': 'API Keys',
    '/dashboard/settings/webhooks': 'Webhooks',
    '/dashboard/settings/billing': 'Billing & Usage',
    '/dashboard/docs': 'Documentation',
  };

  for (const [key, title] of Object.entries(map)) {
    if (pathname === key) return title;
  }

  if (pathname.startsWith('/dashboard/sessions/')) return 'Session Detail';
  if (pathname.startsWith('/dashboard/reports/')) return 'Report Detail';

  return 'Dashboard';
}

export default function Header() {
  const pathname = usePathname();
  const [showDropdown, setShowDropdown] = useState(false);
  const title = getPageTitle(pathname);

  return (
    <header className="flex h-16 items-center justify-between border-b border-slate-700 bg-slate-900/80 px-6 backdrop-blur-sm">
      {/* Page title */}
      <h1 className="text-xl font-semibold text-white">{title}</h1>

      {/* Right side actions */}
      <div className="flex items-center gap-4">
        {/* Search */}
        <div className="relative hidden md:block">
          <svg
            className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            type="text"
            placeholder="Search..."
            className="h-9 w-64 rounded-lg border border-slate-700 bg-slate-800 pl-10 pr-3 text-sm text-slate-100 placeholder:text-slate-500 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>

        {/* Notification bell */}
        <button className="relative rounded-lg p-2 text-slate-400 hover:bg-slate-800 hover:text-white">
          <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
          </svg>
          {/* Count badge */}
          <span className="absolute -right-0.5 -top-0.5 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-[10px] font-bold text-white">
            3
          </span>
        </button>

        {/* User avatar dropdown */}
        <div className="relative">
          <button
            onClick={() => setShowDropdown(!showDropdown)}
            className="flex h-9 w-9 items-center justify-center rounded-full bg-blue-600 text-sm font-semibold text-white hover:bg-blue-700"
          >
            A
          </button>

          {showDropdown && (
            <div className="absolute right-0 top-full z-50 mt-2 w-48 rounded-lg border border-slate-700 bg-slate-800 py-1 shadow-xl">
              <div className="border-b border-slate-700 px-4 py-2">
                <p className="text-sm font-medium text-white">Admin User</p>
                <p className="text-xs text-slate-400">admin@inalign.io</p>
              </div>
              <button
                onClick={() => {
                  setShowDropdown(false);
                  logout();
                }}
                className="flex w-full items-center gap-2 px-4 py-2 text-sm text-slate-300 hover:bg-slate-700 hover:text-white"
              >
                <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                </svg>
                Sign Out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
