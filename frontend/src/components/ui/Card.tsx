import React, { type HTMLAttributes } from 'react';
import { cn } from '@/lib/utils';

// ── Card ────────────────────────────────────────────────────────────────

export function Card({
  className,
  children,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        'rounded-xl border border-slate-700 bg-slate-800 text-slate-100 shadow-lg',
        className,
      )}
      {...props}
    >
      {children}
    </div>
  );
}

// ── CardHeader ──────────────────────────────────────────────────────────

export function CardHeader({
  className,
  children,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn('flex flex-col gap-1.5 px-6 pt-6', className)}
      {...props}
    >
      {children}
    </div>
  );
}

// ── CardTitle ───────────────────────────────────────────────────────────

export function CardTitle({
  className,
  children,
  ...props
}: HTMLAttributes<HTMLHeadingElement>) {
  return (
    <h3
      className={cn('text-lg font-semibold leading-none tracking-tight', className)}
      {...props}
    >
      {children}
    </h3>
  );
}

// ── CardContent ─────────────────────────────────────────────────────────

export function CardContent({
  className,
  children,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn('px-6 py-4', className)} {...props}>
      {children}
    </div>
  );
}

// ── CardFooter ──────────────────────────────────────────────────────────

export function CardFooter({
  className,
  children,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn('flex items-center px-6 pb-6 pt-0', className)}
      {...props}
    >
      {children}
    </div>
  );
}
